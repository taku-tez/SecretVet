import * as https from 'https';
import type { SecretFinding } from './types.js';

export interface AnalysisResult {
  ruleId: string;
  file: string;
  line: number;
  status: 'active' | 'inactive' | 'unknown' | 'error';
  provider: string;
  identity?: {
    user?: string;
    account?: string;
    org?: string;
    email?: string;
  };
  permissions?: {
    scopes?: string[];
    policies?: string[];
    roles?: string[];
    description?: string;
  };
  metadata?: {
    created?: string;
    expires?: string;
    lastUsed?: string;
    tokenType?: string;
    livemode?: boolean;
  };
  riskFlags?: string[];
  checkedAt: string;
}

type Analyzer = (finding: SecretFinding) => Promise<AnalysisResult>;

function httpsRequest(options: https.RequestOptions, body?: string): Promise<{ status: number; body: string; headers: Record<string, string | string[] | undefined> }> {
  return new Promise((resolve, reject) => {
    const req = https.request(options, res => {
      let data = '';
      res.on('data', (chunk: Buffer) => { data += chunk.toString(); });
      res.on('end', () => resolve({
        status: res.statusCode ?? 0,
        body: data,
        headers: res.headers as Record<string, string | string[] | undefined>,
      }));
    });
    req.on('error', reject);
    req.setTimeout(8000, () => { req.destroy(); reject(new Error('timeout')); });
    if (body) req.write(body);
    req.end();
  });
}

function base(finding: SecretFinding, provider: string): AnalysisResult {
  return {
    ruleId: finding.ruleId,
    file: finding.file,
    line: finding.line,
    status: 'unknown',
    provider,
    checkedAt: new Date().toISOString(),
  };
}

function extractValue(finding: SecretFinding): string | null {
  if (finding.match.includes('****')) return null;
  return finding.match.trim().replace(/^['"]|['"]$/g, '');
}

// ---- GitHub ----
async function analyzeGithub(finding: SecretFinding): Promise<AnalysisResult> {
  const result = base(finding, 'GitHub');
  const token = extractValue(finding);
  if (!token) return { ...result, status: 'unknown', riskFlags: ['Token is masked — use --show-secrets to analyze'] };

  try {
    const res = await httpsRequest({
      hostname: 'api.github.com', path: '/user', method: 'GET',
      headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'SecretVet/0.1', Accept: 'application/vnd.github.v3+json' },
    });

    if (res.status === 401) return { ...result, status: 'inactive' };
    if (res.status !== 200) return { ...result, status: 'unknown' };

    const user = JSON.parse(res.body);
    const scopes = String(res.headers['x-oauth-scopes'] ?? '').split(',').map(s => s.trim()).filter(Boolean);

    // Fetch token metadata (fine-grained PATs)
    const tokenRes = await httpsRequest({
      hostname: 'api.github.com', path: '/user/installations', method: 'GET',
      headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'SecretVet/0.1', Accept: 'application/vnd.github.v3+json' },
    }).catch(() => null);

    const riskFlags: string[] = [];
    if (scopes.includes('repo')) riskFlags.push('⚠️  Full repo read/write access');
    if (scopes.includes('admin:org')) riskFlags.push('⚠️  Organization admin access');
    if (scopes.includes('delete_repo')) riskFlags.push('🔴 Can delete repositories!');
    if (scopes.includes('workflow')) riskFlags.push('⚠️  Can modify GitHub Actions workflows');

    return {
      ...result,
      status: 'active',
      identity: { user: user.login, account: String(user.id), email: user.email ?? undefined },
      permissions: { scopes, description: scopes.length === 0 ? 'Fine-grained token (scopes not exposed)' : undefined },
      metadata: { created: user.created_at, tokenType: scopes.length === 0 ? 'fine-grained' : 'classic' },
      riskFlags,
    };
  } catch (err) {
    return { ...result, status: 'error', riskFlags: [String(err)] };
  }
}

// ---- AWS ----
async function analyzeAws(finding: SecretFinding): Promise<AnalysisResult> {
  const result = base(finding, 'AWS');
  const keyId = extractValue(finding);
  if (!keyId) return { ...result, status: 'unknown', riskFlags: ['Key is masked — use --show-secrets to analyze'] };

  try {
    // Probe STS with invalid signature — 403 = key exists, 401 = invalid
    const res = await httpsRequest({
      hostname: 'sts.amazonaws.com',
      path: '/?Action=GetCallerIdentity&Version=2011-06-15',
      method: 'GET',
      headers: {
        Authorization: `AWS4-HMAC-SHA256 Credential=${keyId}/20240101/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=invalid`,
        'x-amz-date': '20240101T000000Z',
      },
    });

    if (res.status === 401 || res.body.includes('InvalidClientTokenId')) {
      return { ...result, status: 'inactive' };
    }
    if (res.status === 403) {
      const riskFlags: string[] = ['Active key ID confirmed (signature check returned 403)'];
      if (keyId.startsWith('ASIA')) riskFlags.push('Temporary session token — likely from STS AssumeRole');
      return { ...result, status: 'active', identity: { account: 'unknown (need secret key to call STS)' }, riskFlags };
    }
    return { ...result, status: 'unknown' };
  } catch (err) {
    return { ...result, status: 'error', riskFlags: [String(err)] };
  }
}

// ---- Stripe ----
async function analyzeStripe(finding: SecretFinding): Promise<AnalysisResult> {
  const result = base(finding, 'Stripe');
  const key = extractValue(finding);
  if (!key) return { ...result, status: 'unknown', riskFlags: ['Key is masked — use --show-secrets to analyze'] };

  try {
    const auth = Buffer.from(`${key}:`).toString('base64');
    const res = await httpsRequest({
      hostname: 'api.stripe.com', path: '/v1/account', method: 'GET',
      headers: { Authorization: `Basic ${auth}` },
    });

    if (res.status === 401) return { ...result, status: 'inactive' };
    if (res.status !== 200) return { ...result, status: 'unknown' };

    const account = JSON.parse(res.body);
    const riskFlags: string[] = [];
    if (account.livemode) riskFlags.push('🔴 LIVE mode key — real money at risk!');
    if (key.startsWith('sk_live_')) riskFlags.push('🔴 Secret key — full API access');
    if (key.startsWith('rk_')) riskFlags.push('Restricted key — check capabilities');

    return {
      ...result,
      status: 'active',
      identity: { account: account.id, org: account.business_profile?.name ?? account.display_name },
      metadata: { livemode: account.livemode, tokenType: key.startsWith('rk_') ? 'restricted' : 'secret' },
      permissions: { description: account.livemode ? 'Live mode — full access to real Stripe account' : 'Test mode' },
      riskFlags,
    };
  } catch (err) {
    return { ...result, status: 'error', riskFlags: [String(err)] };
  }
}

// ---- Slack ----
async function analyzeSlack(finding: SecretFinding): Promise<AnalysisResult> {
  const result = base(finding, 'Slack');
  const token = extractValue(finding);
  if (!token) return { ...result, status: 'unknown', riskFlags: ['Token is masked'] };

  try {
    const res = await httpsRequest({
      hostname: 'slack.com', path: '/api/auth.test', method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    }, '{}');

    if (res.status !== 200) return { ...result, status: 'unknown' };
    const data = JSON.parse(res.body);
    if (!data.ok) return { ...result, status: 'inactive' };

    // Get token info for scopes
    const infoRes = await httpsRequest({
      hostname: 'slack.com', path: '/api/openid.connect.token', method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    }).catch(() => null);

    const riskFlags: string[] = [];
    if (token.startsWith('xoxp-')) riskFlags.push('User token — acts as real user');
    if (token.startsWith('xoxb-')) riskFlags.push('Bot token');
    if (data.is_enterprise_install) riskFlags.push('Enterprise Grid installation');

    return {
      ...result,
      status: 'active',
      identity: { user: data.user, account: data.user_id, org: data.team },
      metadata: { tokenType: token.startsWith('xoxp-') ? 'user' : token.startsWith('xoxb-') ? 'bot' : 'other' },
      riskFlags,
    };
  } catch (err) {
    return { ...result, status: 'error', riskFlags: [String(err)] };
  }
}

// ---- GitLab ----
async function analyzeGitlab(finding: SecretFinding): Promise<AnalysisResult> {
  const result = base(finding, 'GitLab');
  const token = extractValue(finding);
  if (!token) return { ...result, status: 'unknown', riskFlags: ['Token is masked'] };

  try {
    const res = await httpsRequest({
      hostname: 'gitlab.com', path: '/api/v4/personal_access_tokens/self', method: 'GET',
      headers: { 'PRIVATE-TOKEN': token },
    });

    if (res.status === 401) return { ...result, status: 'inactive' };
    if (res.status !== 200) return { ...result, status: 'unknown' };

    const data = JSON.parse(res.body);
    const riskFlags: string[] = [];
    if (data.scopes?.includes('api')) riskFlags.push('⚠️  Full API access');
    if (data.scopes?.includes('write_repository')) riskFlags.push('⚠️  Repository write access');
    if (data.revoked) return { ...result, status: 'inactive' };
    if (data.expires_at) {
      const expiresAt = new Date(data.expires_at);
      if (expiresAt < new Date()) return { ...result, status: 'inactive' };
    }

    return {
      ...result,
      status: 'active',
      identity: { user: data.user_id ? `user:${data.user_id}` : undefined, account: data.name },
      permissions: { scopes: data.scopes ?? [] },
      metadata: { created: data.created_at, expires: data.expires_at ?? 'never', tokenType: 'personal_access_token' },
      riskFlags,
    };
  } catch (err) {
    return { ...result, status: 'error', riskFlags: [String(err)] };
  }
}

// ---- HuggingFace ----
async function analyzeHuggingFace(finding: SecretFinding): Promise<AnalysisResult> {
  const result = base(finding, 'HuggingFace');
  const token = extractValue(finding);
  if (!token) return { ...result, status: 'unknown', riskFlags: ['Token is masked'] };

  try {
    const res = await httpsRequest({
      hostname: 'huggingface.co', path: '/api/whoami-v2', method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });

    if (res.status === 401) return { ...result, status: 'inactive' };
    if (res.status !== 200) return { ...result, status: 'unknown' };

    const data = JSON.parse(res.body);
    const riskFlags: string[] = [];
    if (data.auth?.accessToken?.role === 'write') riskFlags.push('Write access to HuggingFace Hub');
    if (data.orgs?.length > 0) riskFlags.push(`Member of ${data.orgs.length} organization(s)`);

    return {
      ...result,
      status: 'active',
      identity: { user: data.name, email: data.email },
      permissions: { roles: [data.auth?.accessToken?.role ?? 'unknown'], description: `Access to ${data.orgs?.length ?? 0} orgs` },
      riskFlags,
    };
  } catch (err) {
    return { ...result, status: 'error', riskFlags: [String(err)] };
  }
}

// ---- npm ----
async function analyzeNpm(finding: SecretFinding): Promise<AnalysisResult> {
  const result = base(finding, 'npm');
  const token = extractValue(finding);
  if (!token) return { ...result, status: 'unknown', riskFlags: ['Token is masked'] };

  try {
    const res = await httpsRequest({
      hostname: 'registry.npmjs.org', path: '/-/whoami', method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });

    if (res.status === 401) return { ...result, status: 'inactive' };
    if (res.status !== 200) return { ...result, status: 'unknown' };

    const data = JSON.parse(res.body);

    // Get token details
    const tokensRes = await httpsRequest({
      hostname: 'registry.npmjs.org', path: '/-/npm/v1/tokens', method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    }).catch(() => null);

    let tokenType = 'unknown';
    let canPublish = false;
    if (tokensRes?.status === 200) {
      try {
        const tokData = JSON.parse(tokensRes.body);
        const thisToken = tokData.objects?.find((t: any) => t.token && token.startsWith(t.token));
        if (thisToken) { tokenType = thisToken.type; canPublish = thisToken.readonly === false; }
      } catch { /* ignore */ }
    }

    const riskFlags: string[] = [];
    if (canPublish) riskFlags.push('⚠️  Can publish packages to npm registry');

    return {
      ...result,
      status: 'active',
      identity: { user: data.username },
      metadata: { tokenType },
      riskFlags,
    };
  } catch (err) {
    return { ...result, status: 'error', riskFlags: [String(err)] };
  }
}

// ---- Registry ----
const ANALYZERS: Record<string, Analyzer> = {
  'secret-github-pat': analyzeGithub,
  'secret-github-oauth-token': analyzeGithub,
  'secret-github-user-token': analyzeGithub,
  'secret-github-server-token': analyzeGithub,
  'secret-github-fine-grained-pat': analyzeGithub,
  'secret-aws-access-key': analyzeAws,
  'secret-aws-session-token': analyzeAws,
  'secret-stripe-secret-key': analyzeStripe,
  'secret-stripe-restricted-key': analyzeStripe,
  'secret-slack-token': analyzeSlack,
  'secret-gitlab-token': analyzeGitlab,
  'secret-huggingface-token': analyzeHuggingFace,
  'secret-npm-granular-token': analyzeNpm,
  'secret-npm-auth-token': analyzeNpm,
};

export function canAnalyze(ruleId: string): boolean {
  return ruleId in ANALYZERS;
}

export async function analyzeFinding(finding: SecretFinding): Promise<AnalysisResult> {
  const analyzer = ANALYZERS[finding.ruleId];
  if (!analyzer) {
    return {
      ...base(finding, 'unknown'),
      status: 'unknown',
      riskFlags: [`No analyzer available for ${finding.ruleId}`],
    };
  }
  return analyzer(finding);
}

export async function analyzeFindings(
  findings: SecretFinding[],
  onProgress?: (result: AnalysisResult, index: number, total: number) => void,
): Promise<AnalysisResult[]> {
  const results: AnalysisResult[] = [];
  const analyzable = findings.filter(f => canAnalyze(f.ruleId));

  for (let i = 0; i < analyzable.length; i++) {
    const result = await analyzeFinding(analyzable[i]);
    results.push(result);
    onProgress?.(result, i + 1, analyzable.length);
    if (i < analyzable.length - 1) await new Promise(r => setTimeout(r, 300));
  }

  return results;
}

export function formatAnalysisResult(result: AnalysisResult): string {
  const lines: string[] = [];
  const icon = result.status === 'active' ? '🔴 ACTIVE' : result.status === 'inactive' ? '✅ REVOKED' : '❓ UNKNOWN';

  lines.push(`  ${icon}  [${result.provider}] ${result.ruleId}`);
  lines.push(`  ${result.file}:${result.line}`);

  if (result.identity) {
    const id = result.identity;
    if (id.user) lines.push(`  👤 User:    ${id.user}`);
    if (id.account) lines.push(`  🏢 Account: ${id.account}`);
    if (id.org) lines.push(`  🏭 Org:     ${id.org}`);
    if (id.email) lines.push(`  📧 Email:   ${id.email}`);
  }

  if (result.permissions) {
    const p = result.permissions;
    if (p.scopes?.length) lines.push(`  🔑 Scopes:  ${p.scopes.join(', ')}`);
    if (p.policies?.length) lines.push(`  📋 Policies: ${p.policies.join(', ')}`);
    if (p.description) lines.push(`  📝 Access:  ${p.description}`);
  }

  if (result.metadata) {
    const m = result.metadata;
    if (m.tokenType) lines.push(`  🏷️  Type:    ${m.tokenType}`);
    if (m.livemode !== undefined) lines.push(`  ⚡ Mode:    ${m.livemode ? 'LIVE 🔴' : 'test'}`);
    if (m.expires) lines.push(`  ⏰ Expires: ${m.expires}`);
    if (m.created) lines.push(`  📅 Created: ${m.created.slice(0, 10)}`);
  }

  if (result.riskFlags?.length) {
    lines.push(`  ⚠️  Risks:`);
    for (const flag of result.riskFlags) lines.push(`     ${flag}`);
  }

  return lines.join('\n');
}
