import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execSync, spawnSync } from 'child_process';
import { scan } from './scanner.js';
import type { ScanResult, ScanOptions } from './types.js';

const VERSION = '0.1.0';

export interface RemoteScanOptions extends ScanOptions {
  depth?: number;
  branch?: string;
  githubToken?: string;
  gitlabToken?: string;
}

// Parse supported URL formats into a clone URL
function resolveCloneUrl(input: string, token?: string): { url: string; provider: 'github' | 'gitlab' | 'bitbucket' | 'generic' } {
  // github:owner/repo shorthand
  const ghShorthand = /^github:([^/]+\/[^/]+)$/.exec(input);
  if (ghShorthand) {
    const url = token
      ? `https://${token}@github.com/${ghShorthand[1]}.git`
      : `https://github.com/${ghShorthand[1]}.git`;
    return { url, provider: 'github' };
  }

  // gitlab:owner/repo shorthand
  const glShorthand = /^gitlab:([^/]+\/[^/]+)$/.exec(input);
  if (glShorthand) {
    const url = token
      ? `https://oauth2:${token}@gitlab.com/${glShorthand[1]}.git`
      : `https://gitlab.com/${glShorthand[1]}.git`;
    return { url, provider: 'gitlab' };
  }

  // Full https://github.com/owner/repo URL
  const ghUrl = /^https?:\/\/github\.com\/([^/]+\/[^/\s]+?)(?:\.git)?(?:\/.*)?$/.exec(input);
  if (ghUrl) {
    const url = token
      ? `https://${token}@github.com/${ghUrl[1]}.git`
      : `https://github.com/${ghUrl[1]}.git`;
    return { url, provider: 'github' };
  }

  // Full https://gitlab.com/owner/repo URL
  const glUrl = /^https?:\/\/gitlab\.com\/([^/]+\/[^/\s]+?)(?:\.git)?(?:\/.*)?$/.exec(input);
  if (glUrl) {
    const url = token
      ? `https://oauth2:${token}@gitlab.com/${glUrl[1]}.git`
      : `https://gitlab.com/${glUrl[1]}.git`;
    return { url, provider: 'gitlab' };
  }

  // Bitbucket
  const bbUrl = /^https?:\/\/bitbucket\.org\/([^/]+\/[^/\s]+?)(?:\.git)?(?:\/.*)?$/.exec(input);
  if (bbUrl) {
    return { url: input.endsWith('.git') ? input : `${input}.git`, provider: 'bitbucket' };
  }

  // Bare git URL
  if (input.endsWith('.git') || input.startsWith('git@') || input.startsWith('https://')) {
    return { url: input, provider: 'generic' };
  }

  throw new Error(`Unsupported repository URL format: ${input}\nSupported formats: github:owner/repo, https://github.com/owner/repo, https://gitlab.com/owner/repo`);
}

/**
 * CVE-2025-41390 mitigation:
 * Always clone to a temporary directory before scanning, even for local repos.
 * This prevents malicious git config attacks.
 */
async function safeClone(cloneUrl: string, tmpDir: string, options: RemoteScanOptions): Promise<void> {
  const depth = options.depth ?? (options as any).gitHistory ? undefined : 1;
  const branch = options.branch;

  const args = ['clone', '--no-local'];
  if (depth) args.push(`--depth=${depth}`);
  if (branch) args.push('--branch', branch);

  // Prevent git config injection via safe.directory
  args.push('-c', `safe.directory=${tmpDir}`);
  args.push('-c', 'core.hooksPath=/dev/null'); // Disable git hooks
  args.push('-c', 'protocol.file.allow=never'); // Block file:// protocol attacks

  args.push(cloneUrl, tmpDir);

  const token = options.githubToken ?? options.gitlabToken ?? process.env.GITHUB_TOKEN ?? process.env.GITLAB_TOKEN;
  const env: Record<string, string> = {
    ...process.env as Record<string, string>,
    GIT_ASKPASS: 'echo',
    GIT_TERMINAL_PROMPT: '0',
    GIT_CONFIG_NOSYSTEM: '1',
  };

  const result = spawnSync('git', args, {
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 120_000,
  });

  if (result.error) throw new Error(`git clone failed: ${result.error.message}`);
  if (result.status !== 0) {
    const stderr = result.stderr?.toString() ?? '';
    // Sanitize token from error messages
    const sanitized = token ? stderr.replace(new RegExp(token, 'g'), '***') : stderr;
    throw new Error(`git clone failed (exit ${result.status}): ${sanitized}`);
  }
}

export async function scanRemote(input: string, options: RemoteScanOptions = {}): Promise<ScanResult> {
  const token = options.githubToken
    ?? options.gitlabToken
    ?? process.env.GITHUB_TOKEN
    ?? process.env.GITLAB_TOKEN;

  const { url: cloneUrl } = resolveCloneUrl(input, token);

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretvet-remote-'));

  // Register cleanup handlers for SIGINT/SIGTERM
  const cleanup = () => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  };
  process.once('SIGINT', cleanup);
  process.once('SIGTERM', cleanup);
  process.once('exit', cleanup);

  try {
    await safeClone(cloneUrl, tmpDir, options);
    const result = await scan(tmpDir, options);

    // Replace tmpDir paths with the original remote URL
    const remoteLabel = input.replace(/https?:\/\/[^@]+@/, 'https://'); // strip token from display
    result.target = remoteLabel;
    result.findings = result.findings.map(f => ({
      ...f,
      file: f.file.replace(tmpDir, '').replace(/^\//, ''),
    }));

    return result;
  } finally {
    cleanup();
    process.off('SIGINT', cleanup);
    process.off('SIGTERM', cleanup);
    process.off('exit', cleanup);
  }
}

export function isRemoteUrl(input: string): boolean {
  return /^(github|gitlab|bitbucket):/.test(input)
    || /^https?:\/\/(github|gitlab|bitbucket)\./.test(input)
    || (input.endsWith('.git') && !fs.existsSync(input));
}
