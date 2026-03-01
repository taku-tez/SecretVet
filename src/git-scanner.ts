import { execSync, spawnSync } from 'child_process';
import * as path from 'path';
import { ALL_RULES } from './rules/index.js';
import { scanFile } from './scanner.js';
import type { SecretFinding, ScanOptions } from './types.js';

export interface GitFinding extends SecretFinding {
  gitCommit: string;
  gitAuthor: string;
  gitDate: string;
  gitMessage: string;
}

export interface GitScanOptions extends ScanOptions {
  since?: string;
  until?: string;
  branch?: string;
  maxCommits?: number;
}

export interface GitScanResult {
  repoPath: string;
  timestamp: string;
  duration: number;
  commitsScanned: number;
  findings: GitFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  version: string;
}

const VERSION = '0.1.0';

function isGitRepo(dir: string): boolean {
  try {
    execSync('git rev-parse --git-dir', { cwd: dir, stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

interface CommitInfo {
  hash: string;
  author: string;
  date: string;
  message: string;
}

function getCommits(repoPath: string, options: GitScanOptions): CommitInfo[] {
  const args = ['log', '--format=%H%x00%ae%x00%aI%x00%s'];

  if (options.since) args.push(`--since=${options.since}`);
  if (options.until) args.push(`--until=${options.until}`);
  if (options.branch) args.push(options.branch);
  if (options.maxCommits) args.push(`-n`, String(options.maxCommits));

  const result = spawnSync('git', args, { cwd: repoPath, encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 });

  if (result.error || result.status !== 0) return [];

  return result.stdout
    .split('\n')
    .filter(Boolean)
    .map(line => {
      const [hash, author, date, ...msgParts] = line.split('\x00');
      return { hash, author, date, message: msgParts.join('\x00') };
    });
}

function getCommitFiles(repoPath: string, commit: string): string[] {
  const result = spawnSync('git', ['diff-tree', '--no-commit-id', '-r', '--name-only', commit], {
    cwd: repoPath,
    encoding: 'utf-8',
    maxBuffer: 10 * 1024 * 1024,
  });

  if (result.error || result.status !== 0) return [];
  return result.stdout.split('\n').filter(Boolean);
}

function getFileAtCommit(repoPath: string, commit: string, filePath: string): string | null {
  const result = spawnSync('git', ['show', `${commit}:${filePath}`], {
    cwd: repoPath,
    encoding: 'utf-8',
    maxBuffer: 2 * 1024 * 1024,
  });

  if (result.error || result.status !== 0) return null;
  return result.stdout;
}

const BINARY_EXTENSIONS = new Set([
  '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.pdf',
  '.zip', '.tar', '.gz', '.bz2', '.7z', '.exe', '.dll',
  '.so', '.dylib', '.bin', '.wasm', '.pyc', '.class',
  '.db', '.sqlite', '.lock',
]);

export async function scanGitHistory(repoPath: string, options: GitScanOptions = {}): Promise<GitScanResult> {
  const start = Date.now();
  const allFindings: GitFinding[] = [];

  if (!isGitRepo(repoPath)) {
    throw new Error(`Not a git repository: ${repoPath}`);
  }

  const commits = getCommits(repoPath, options);
  let commitsScanned = 0;

  const seenFileContents = new Map<string, Set<string>>();

  for (const commit of commits) {
    const files = getCommitFiles(repoPath, commit.hash);

    for (const filePath of files) {
      const ext = path.extname(filePath).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext)) continue;

      const content = getFileAtCommit(repoPath, commit.hash, filePath);
      if (!content) continue;

      // Dedup: skip if we've seen this exact content for this path before
      const key = filePath;
      if (!seenFileContents.has(key)) seenFileContents.set(key, new Set());
      const contentHash = content.slice(0, 200); // quick fingerprint
      if (seenFileContents.get(key)!.has(contentHash)) continue;
      seenFileContents.get(key)!.add(contentHash);

      // Write to temp file for scanning
      const tmpContent = content;
      const tmpFindings = await scanContentAsFile(tmpContent, filePath, options);

      for (const f of tmpFindings) {
        allFindings.push({
          ...f,
          gitCommit: commit.hash.slice(0, 8),
          gitAuthor: commit.author,
          gitDate: commit.date,
          gitMessage: commit.message,
        });
      }
    }

    commitsScanned++;
  }

  const summary = {
    critical: allFindings.filter(f => f.severity === 'critical').length,
    high: allFindings.filter(f => f.severity === 'high').length,
    medium: allFindings.filter(f => f.severity === 'medium').length,
    low: allFindings.filter(f => f.severity === 'low').length,
    info: allFindings.filter(f => f.severity === 'info').length,
    total: allFindings.length,
  };

  return {
    repoPath,
    timestamp: new Date().toISOString(),
    duration: Date.now() - start,
    commitsScanned,
    findings: allFindings,
    summary,
    version: VERSION,
  };
}

async function scanContentAsFile(content: string, filePath: string, options: ScanOptions): Promise<SecretFinding[]> {
  const fs = await import('fs');
  const os = await import('os');
  const pathMod = await import('path');

  const tmpDir = os.tmpdir();
  const tmpFile = pathMod.join(tmpDir, `secretvet-${Date.now()}-${Math.random().toString(36).slice(2)}`);

  try {
    fs.writeFileSync(tmpFile, content, 'utf-8');
    const { findings } = await scanFile(tmpFile, ALL_RULES, options);
    // Fix file path to show original path
    return findings.map(f => ({ ...f, file: filePath }));
  } finally {
    try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
  }
}

export async function scanStagedFiles(repoPath: string, options: ScanOptions = {}): Promise<SecretFinding[]> {
  if (!isGitRepo(repoPath)) {
    throw new Error(`Not a git repository: ${repoPath}`);
  }

  const result = spawnSync('git', ['diff', '--cached', '--name-only'], {
    cwd: repoPath,
    encoding: 'utf-8',
  });

  if (result.error || result.status !== 0) return [];

  const stagedFiles = result.stdout.split('\n').filter(Boolean);
  const allFindings: SecretFinding[] = [];

  for (const filePath of stagedFiles) {
    const ext = path.extname(filePath).toLowerCase();
    if (BINARY_EXTENSIONS.has(ext)) continue;

    // Get staged content
    const contentResult = spawnSync('git', ['show', `:${filePath}`], {
      cwd: repoPath,
      encoding: 'utf-8',
      maxBuffer: 2 * 1024 * 1024,
    });

    if (contentResult.error || contentResult.status !== 0) continue;

    const findings = await scanContentAsFile(contentResult.stdout, filePath, options);
    allFindings.push(...findings);
  }

  return allFindings;
}
