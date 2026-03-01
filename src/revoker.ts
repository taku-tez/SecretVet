import * as https from 'https';
import * as readline from 'readline';
import type { SecretFinding } from './types.js';

export interface RevokeResult {
  ruleId: string;
  file: string;
  line: number;
  status: 'revoked' | 'failed' | 'skipped' | 'unsupported';
  message: string;
}

function httpsRequest(
  options: https.RequestOptions,
  body?: string
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = https.request(options, res => {
      let data = '';
      res.on('data', (chunk: Buffer) => { data += chunk.toString(); });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data }));
    });
    req.on('error', reject);
    req.setTimeout(8000, () => { req.destroy(); reject(new Error('timeout')); });
    if (body) req.write(body);
    req.end();
  });
}

function extractValue(finding: SecretFinding): string | null {
  if (finding.match.includes('****')) return null;
  return finding.match.trim().replace(/^['"]|['"]$/g, '');
}

// ---- Revokers ----

async function revokeGithubToken(finding: SecretFinding): Promise<RevokeResult> {
  const base = { ruleId: finding.ruleId, file: finding.file, line: finding.line };
  const token = extractValue(finding);
  if (!token) return { ...base, status: 'failed', message: 'Cannot revoke masked token. Use --show-secrets.' };

  try {
    const res = await httpsRequest({
      hostname: 'api.github.com',
      path: '/installation/token',
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'SecretVet/0.1', Accept: 'application/vnd.github.v3+json' },
    });

    if (res.status === 204 || res.status === 200) {
      return { ...base, status: 'revoked', message: 'GitHub token revoked successfully.' };
    }
    // Try user token revocation
    const res2 = await httpsRequest({
      hostname: 'api.github.com',
      path: '/user/tokens/self',
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'SecretVet/0.1', Accept: 'application/vnd.github.v3+json' },
    });
    if (res2.status === 204 || res2.status === 200) {
      return { ...base, status: 'revoked', message: 'GitHub token revoked successfully.' };
    }
    return { ...base, status: 'failed', message: `GitHub API returned ${res2.status}. Revoke manually at github.com/settings/tokens.` };
  } catch (err) {
    return { ...base, status: 'failed', message: `Request failed: ${err instanceof Error ? err.message : String(err)}` };
  }
}

async function revokeGitLabToken(finding: SecretFinding): Promise<RevokeResult> {
  const base = { ruleId: finding.ruleId, file: finding.file, line: finding.line };
  const token = extractValue(finding);
  if (!token) return { ...base, status: 'failed', message: 'Cannot revoke masked token.' };

  try {
    const res = await httpsRequest({
      hostname: 'gitlab.com',
      path: '/api/v4/personal_access_tokens/self',
      method: 'DELETE',
      headers: { 'PRIVATE-TOKEN': token },
    });

    if (res.status === 204 || res.status === 200) {
      return { ...base, status: 'revoked', message: 'GitLab token revoked successfully.' };
    }
    return { ...base, status: 'failed', message: `GitLab API returned ${res.status}. Revoke manually at gitlab.com/-/profile/personal_access_tokens.` };
  } catch (err) {
    return { ...base, status: 'failed', message: String(err) };
  }
}

async function revokeNpmToken(finding: SecretFinding): Promise<RevokeResult> {
  const base = { ruleId: finding.ruleId, file: finding.file, line: finding.line };
  const token = extractValue(finding);
  if (!token) return { ...base, status: 'failed', message: 'Cannot revoke masked token.' };

  try {
    // First get the token UUID
    const listRes = await httpsRequest({
      hostname: 'registry.npmjs.org',
      path: '/-/npm/v1/tokens',
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });

    if (listRes.status !== 200) {
      return { ...base, status: 'failed', message: 'Could not list tokens. Revoke manually at npmjs.com/settings/tokens.' };
    }

    const tokenData = JSON.parse(listRes.body);
    const thisToken = tokenData.objects?.find((t: any) => t.token && token.startsWith(t.token));

    if (!thisToken?.key) {
      return { ...base, status: 'failed', message: 'Token not found in list. It may already be revoked.' };
    }

    const revokeRes = await httpsRequest({
      hostname: 'registry.npmjs.org',
      path: `/-/npm/v1/tokens/token/${thisToken.key}`,
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });

    if (revokeRes.status === 204 || revokeRes.status === 200) {
      return { ...base, status: 'revoked', message: 'npm token revoked successfully.' };
    }
    return { ...base, status: 'failed', message: `npm API returned ${revokeRes.status}. Revoke manually at npmjs.com/settings/tokens.` };
  } catch (err) {
    return { ...base, status: 'failed', message: String(err) };
  }
}

function unsupported(finding: SecretFinding, hint: string): Promise<RevokeResult> {
  return Promise.resolve({
    ruleId: finding.ruleId,
    file: finding.file,
    line: finding.line,
    status: 'unsupported' as const,
    message: hint,
  });
}

const REVOKERS: Record<string, (f: SecretFinding) => Promise<RevokeResult>> = {
  'secret-github-pat': revokeGithubToken,
  'secret-github-oauth-token': revokeGithubToken,
  'secret-github-user-token': revokeGithubToken,
  'secret-github-server-token': revokeGithubToken,
  'secret-github-fine-grained-pat': revokeGithubToken,
  'secret-gitlab-token': revokeGitLabToken,
  'secret-npm-granular-token': revokeNpmToken,
  'secret-npm-auth-token': revokeNpmToken,
};

const MANUAL_REVOKE_URLS: Record<string, string> = {
  'secret-aws-access-key': 'https://console.aws.amazon.com/iam/home#/security_credentials',
  'secret-openai-key': 'https://platform.openai.com/api-keys',
  'secret-anthropic-key': 'https://console.anthropic.com/settings/keys',
  'secret-stripe-secret-key': 'https://dashboard.stripe.com/apikeys',
  'secret-slack-token': 'https://api.slack.com/apps',
  'secret-huggingface-token': 'https://huggingface.co/settings/tokens',
  'secret-discord-bot-token': 'https://discord.com/developers/applications',
  'secret-sendgrid-key': 'https://app.sendgrid.com/settings/api_keys',
  'secret-datadog-api-key': 'https://app.datadoghq.com/organization-settings/api-keys',
  'secret-vercel-token': 'https://vercel.com/account/tokens',
  'secret-notion-integration-token': 'https://notion.so/my-integrations',
};

export function canRevoke(ruleId: string): boolean {
  return ruleId in REVOKERS || ruleId in MANUAL_REVOKE_URLS;
}

export function getManualRevokeUrl(ruleId: string): string | undefined {
  return MANUAL_REVOKE_URLS[ruleId];
}

export async function revokeFinding(finding: SecretFinding, dryRun = false): Promise<RevokeResult> {
  const revoker = REVOKERS[finding.ruleId];

  if (!revoker) {
    const url = MANUAL_REVOKE_URLS[finding.ruleId];
    if (url) {
      return {
        ruleId: finding.ruleId,
        file: finding.file,
        line: finding.line,
        status: 'unsupported',
        message: `Manual revocation required. Visit: ${url}`,
      };
    }
    return {
      ruleId: finding.ruleId,
      file: finding.file,
      line: finding.line,
      status: 'unsupported',
      message: 'Automatic revocation not supported for this secret type.',
    };
  }

  if (dryRun) {
    return {
      ruleId: finding.ruleId,
      file: finding.file,
      line: finding.line,
      status: 'skipped',
      message: '[dry-run] Would revoke via API.',
    };
  }

  return revoker(finding);
}

// ---- Interactive triage ----

async function prompt(question: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => {
    rl.question(question, answer => { rl.close(); resolve(answer.trim().toLowerCase()); });
  });
}

export async function triage(
  findings: SecretFinding[],
  options: { dryRun?: boolean; showSecrets?: boolean } = {}
): Promise<void> {
  if (findings.length === 0) {
    console.log('No findings to triage.');
    return;
  }

  console.log(`\n🔐 SecretVet Triage — ${findings.length} finding(s)\n`);

  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    const autoRevoke = canRevoke(f.ruleId) && f.ruleId in REVOKERS;
    const manualUrl = getManualRevokeUrl(f.ruleId);

    console.log(`\n[${ i + 1}/${findings.length}] ${f.severity.toUpperCase()} — ${f.ruleName}`);
    console.log(`  File:  ${f.file}:${f.line}`);
    console.log(`  Match: ${f.match}`);
    console.log('');
    console.log('  Actions:');
    if (autoRevoke) console.log('    [r] Revoke via API automatically');
    if (manualUrl) console.log(`    [m] Open revoke URL: ${manualUrl}`);
    console.log('    [b] Add to baseline (suppress future reports)');
    console.log('    [s] Skip');
    console.log('    [q] Quit');
    console.log('');

    const choice = await prompt('  Choice: ');

    if (choice === 'q') {
      console.log('\nTriage stopped.');
      break;
    } else if (choice === 'r' && autoRevoke) {
      console.log('  → Revoking...');
      const result = await revokeFinding(f, options.dryRun);
      const icon = result.status === 'revoked' ? '✅' : result.status === 'skipped' ? '⏭️' : '❌';
      console.log(`  ${icon} ${result.message}`);
    } else if (choice === 'm' && manualUrl) {
      console.log(`  → Open in browser: ${manualUrl}`);
      // Attempt to open browser
      const { spawnSync } = await import('child_process');
      const opener = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
      spawnSync(opener, [manualUrl], { stdio: 'ignore' });
    } else if (choice === 'b') {
      console.log('  → Added to baseline (run: secretvet baseline update .)');
    } else if (choice === 's') {
      console.log('  → Skipped.');
    } else {
      console.log('  → Invalid choice, skipping.');
    }
  }

  console.log('\n✅ Triage complete.\n');
}
