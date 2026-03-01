import * as https from 'https';
import type { SecretFinding } from './types.js';

export interface VerifyResult {
  ruleId: string;
  file: string;
  line: number;
  status: 'active' | 'inactive' | 'unknown' | 'error';
  message: string;
  checkedAt: string;
}

type Verifier = (finding: SecretFinding) => Promise<VerifyResult>;

function httpsRequest(options: https.RequestOptions, body?: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk: Buffer) => { data += chunk.toString(); });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data }));
    });
    req.on('error', reject);
    req.setTimeout(5000, () => { req.destroy(); reject(new Error('timeout')); });
    if (body) req.write(body);
    req.end();
  });
}

function makeResult(finding: SecretFinding, status: VerifyResult['status'], message: string): VerifyResult {
  return {
    ruleId: finding.ruleId,
    file: finding.file,
    line: finding.line,
    status,
    message,
    checkedAt: new Date().toISOString(),
  };
}

// Extract raw secret value from masked match (best-effort, needs --show-secrets)
function extractValue(finding: SecretFinding): string | null {
  // If masked (contains ****), we can't verify
  if (finding.match.includes('****')) return null;
  return finding.match.trim().replace(/^['"]|['"]$/g, '');
}

// --- Rule-specific verifiers ---

async function verifyAwsAccessKey(finding: SecretFinding): Promise<VerifyResult> {
  const key = extractValue(finding);
  if (!key) return makeResult(finding, 'unknown', 'Cannot verify masked secret. Use --show-secrets with --verify.');

  try {
    // AWS STS GetCallerIdentity — works without a secret key to check if key ID exists
    // We check via a lightweight request that returns 403 (key exists but no secret) vs 401 (invalid key)
    const res = await httpsRequest({
      hostname: 'sts.amazonaws.com',
      path: '/?Action=GetCallerIdentity&Version=2011-06-15',
      method: 'GET',
      headers: {
        'Authorization': `AWS4-HMAC-SHA256 Credential=${key}/20240101/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=invalid`,
        'x-amz-date': '20240101T000000Z',
      },
    });

    if (res.status === 403) {
      return makeResult(finding, 'active', 'AWS Access Key ID appears valid (key exists, signature rejected as expected).');
    } else if (res.status === 401 || res.body.includes('InvalidClientTokenId')) {
      return makeResult(finding, 'inactive', 'AWS Access Key ID is invalid or revoked.');
    }
    return makeResult(finding, 'unknown', `Unexpected response status: ${res.status}`);
  } catch (err) {
    return makeResult(finding, 'error', `Verification failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function verifyGithubToken(finding: SecretFinding): Promise<VerifyResult> {
  const token = extractValue(finding);
  if (!token) return makeResult(finding, 'unknown', 'Cannot verify masked secret. Use --show-secrets with --verify.');

  try {
    const res = await httpsRequest({
      hostname: 'api.github.com',
      path: '/user',
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'User-Agent': 'SecretVet-Verifier/0.1',
        'Accept': 'application/vnd.github.v3+json',
      },
    });

    if (res.status === 200) {
      let login = 'unknown';
      try { login = JSON.parse(res.body).login ?? 'unknown'; } catch { /* ignore */ }
      return makeResult(finding, 'active', `GitHub token is ACTIVE — authenticated as: ${login}`);
    } else if (res.status === 401) {
      return makeResult(finding, 'inactive', 'GitHub token is invalid or revoked.');
    }
    return makeResult(finding, 'unknown', `Unexpected response status: ${res.status}`);
  } catch (err) {
    return makeResult(finding, 'error', `Verification failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function verifySlackToken(finding: SecretFinding): Promise<VerifyResult> {
  const token = extractValue(finding);
  if (!token) return makeResult(finding, 'unknown', 'Cannot verify masked secret. Use --show-secrets with --verify.');

  try {
    const res = await httpsRequest({
      hostname: 'slack.com',
      path: '/api/auth.test',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    }, '{}');

    if (res.status === 200) {
      try {
        const json = JSON.parse(res.body);
        if (json.ok) {
          return makeResult(finding, 'active', `Slack token is ACTIVE — team: ${json.team ?? 'unknown'}, user: ${json.user ?? 'unknown'}`);
        } else {
          return makeResult(finding, 'inactive', `Slack token is invalid: ${json.error ?? 'unknown error'}`);
        }
      } catch {
        return makeResult(finding, 'unknown', 'Failed to parse Slack API response.');
      }
    }
    return makeResult(finding, 'unknown', `Unexpected response status: ${res.status}`);
  } catch (err) {
    return makeResult(finding, 'error', `Verification failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function verifyStripeKey(finding: SecretFinding): Promise<VerifyResult> {
  const key = extractValue(finding);
  if (!key) return makeResult(finding, 'unknown', 'Cannot verify masked secret. Use --show-secrets with --verify.');

  try {
    const auth = Buffer.from(`${key}:`).toString('base64');
    const res = await httpsRequest({
      hostname: 'api.stripe.com',
      path: '/v1/account',
      method: 'GET',
      headers: { 'Authorization': `Basic ${auth}` },
    });

    if (res.status === 200) {
      return makeResult(finding, 'active', 'Stripe key is ACTIVE — account accessible.');
    } else if (res.status === 401) {
      return makeResult(finding, 'inactive', 'Stripe key is invalid or revoked.');
    }
    return makeResult(finding, 'unknown', `Unexpected response status: ${res.status}`);
  } catch (err) {
    return makeResult(finding, 'error', `Verification failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function verifyHuggingFaceToken(finding: SecretFinding): Promise<VerifyResult> {
  const token = extractValue(finding);
  if (!token) return makeResult(finding, 'unknown', 'Cannot verify masked secret. Use --show-secrets with --verify.');

  try {
    const res = await httpsRequest({
      hostname: 'huggingface.co',
      path: '/api/whoami-v2',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` },
    });

    if (res.status === 200) {
      let name = 'unknown';
      try { name = JSON.parse(res.body).name ?? 'unknown'; } catch { /* ignore */ }
      return makeResult(finding, 'active', `HuggingFace token is ACTIVE — user: ${name}`);
    } else if (res.status === 401) {
      return makeResult(finding, 'inactive', 'HuggingFace token is invalid or revoked.');
    }
    return makeResult(finding, 'unknown', `Unexpected response status: ${res.status}`);
  } catch (err) {
    return makeResult(finding, 'error', `Verification failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function verifyGitLabToken(finding: SecretFinding): Promise<VerifyResult> {
  const token = extractValue(finding);
  if (!token) return makeResult(finding, 'unknown', 'Cannot verify masked secret. Use --show-secrets with --verify.');

  try {
    const res = await httpsRequest({
      hostname: 'gitlab.com',
      path: '/api/v4/user',
      method: 'GET',
      headers: { 'PRIVATE-TOKEN': token },
    });

    if (res.status === 200) {
      let username = 'unknown';
      try { username = JSON.parse(res.body).username ?? 'unknown'; } catch { /* ignore */ }
      return makeResult(finding, 'active', `GitLab token is ACTIVE — user: ${username}`);
    } else if (res.status === 401) {
      return makeResult(finding, 'inactive', 'GitLab token is invalid or revoked.');
    }
    return makeResult(finding, 'unknown', `Unexpected response status: ${res.status}`);
  } catch (err) {
    return makeResult(finding, 'error', `Verification failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function verifyNpmToken(finding: SecretFinding): Promise<VerifyResult> {
  const token = extractValue(finding);
  if (!token) return makeResult(finding, 'unknown', 'Cannot verify masked secret. Use --show-secrets with --verify.');

  try {
    const res = await httpsRequest({
      hostname: 'registry.npmjs.org',
      path: '/-/whoami',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` },
    });

    if (res.status === 200) {
      let username = 'unknown';
      try { username = JSON.parse(res.body).username ?? 'unknown'; } catch { /* ignore */ }
      return makeResult(finding, 'active', `npm token is ACTIVE — user: ${username}`);
    } else if (res.status === 401) {
      return makeResult(finding, 'inactive', 'npm token is invalid or revoked.');
    }
    return makeResult(finding, 'unknown', `Unexpected response status: ${res.status}`);
  } catch (err) {
    return makeResult(finding, 'error', `Verification failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

// --- Registry ---

const VERIFIERS: Record<string, Verifier> = {
  'secret-aws-access-key': verifyAwsAccessKey,
  'secret-github-pat': verifyGithubToken,
  'secret-github-oauth-token': verifyGithubToken,
  'secret-github-user-token': verifyGithubToken,
  'secret-github-server-token': verifyGithubToken,
  'secret-github-fine-grained-pat': verifyGithubToken,
  'secret-slack-token': verifySlackToken,
  'secret-stripe-secret-key': verifyStripeKey,
  'secret-stripe-restricted-key': verifyStripeKey,
  'secret-huggingface-token': verifyHuggingFaceToken,
  'secret-gitlab-token': verifyGitLabToken,
  'secret-npm-granular-token': verifyNpmToken,
  'secret-npm-auth-token': verifyNpmToken,
};

export function canVerify(ruleId: string): boolean {
  return ruleId in VERIFIERS;
}

export async function verifyFinding(finding: SecretFinding): Promise<VerifyResult> {
  const verifier = VERIFIERS[finding.ruleId];
  if (!verifier) {
    return makeResult(finding, 'unknown', `No verifier available for rule: ${finding.ruleId}`);
  }
  return verifier(finding);
}

export async function verifyFindings(findings: SecretFinding[]): Promise<VerifyResult[]> {
  const results: VerifyResult[] = [];

  for (const finding of findings) {
    const result = await verifyFinding(finding);
    results.push(result);

    // Rate limit: 200ms between requests
    await new Promise(r => setTimeout(r, 200));
  }

  return results;
}
