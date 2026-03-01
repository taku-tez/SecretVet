import type { SecretRule } from '../types.js';

const PLACEHOLDER_RE = /your[_-]?(api[_-]?)?key|example|dummy|placeholder|xxx+|test[_-]?key|fake|sample|changeme|\*{4,}/i;
const fp = (match: string) => PLACEHOLDER_RE.test(match);

export const rules: SecretRule[] = [
  // Okta
  {
    id: 'secret-okta-api-token',
    name: 'Okta API Token',
    description: 'Okta Identity Platform API token detected',
    severity: 'critical',
    category: 'identity',
    pattern: /(?:okta)[_\-.]?(?:api[_\-.]?)?token\s*[=:'"]+\s*['"]?([0-9A-Za-z_\-]{42})['"]?/gi,
    recommendation: 'Rotate this Okta API token at your Okta Admin Console > Security > API.',
    falsePositiveFilter: fp,
  },
  {
    id: 'secret-okta-client-secret',
    name: 'Okta Client Secret',
    description: 'Okta OAuth application client secret detected',
    severity: 'critical',
    category: 'identity',
    pattern: /(?:okta)[_\-.]?client[_\-.]?secret\s*[=:'"]+\s*['"]?([A-Za-z0-9_\-]{40,64})['"]?/gi,
    recommendation: 'Rotate this Okta client secret in your application settings.',
    falsePositiveFilter: fp,
  },

  // Auth0
  {
    id: 'secret-auth0-client-secret',
    name: 'Auth0 Client Secret',
    description: 'Auth0 application client secret detected',
    severity: 'critical',
    category: 'identity',
    pattern: /(?:auth0)[_\-.]?client[_\-.]?secret\s*[=:'"]+\s*['"]?([A-Za-z0-9_\-]{43,86})['"]?/gi,
    recommendation: 'Rotate this Auth0 client secret in the Auth0 Dashboard.',
    falsePositiveFilter: fp,
  },
  {
    id: 'secret-auth0-management-token',
    name: 'Auth0 Management API Token',
    description: 'Auth0 Management API token detected',
    severity: 'critical',
    category: 'identity',
    pattern: /(?:auth0)[_\-.]?(?:management[_\-.]?)?(?:api[_\-.]?)?token\s*[=:'"]+\s*['"]?(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)['"]?/gi,
    recommendation: 'Revoke this Auth0 Management API token immediately.',
    falsePositiveFilter: fp,
  },

  // Doppler
  {
    id: 'secret-doppler-service-token',
    name: 'Doppler Service Token',
    description: 'Doppler secrets manager service token detected',
    severity: 'critical',
    category: 'identity',
    pattern: /\bdp\.st\.[a-zA-Z0-9_\-]{43,}\b/g,
    recommendation: 'Rotate this Doppler service token at dashboard.doppler.com.',
    falsePositiveFilter: fp,
  },
  {
    id: 'secret-doppler-personal-token',
    name: 'Doppler Personal Token',
    description: 'Doppler personal token detected',
    severity: 'high',
    category: 'identity',
    pattern: /\bdp\.pt\.[a-zA-Z0-9_\-]{43,}\b/g,
    recommendation: 'Rotate this Doppler personal token.',
    falsePositiveFilter: fp,
  },

  // 1Password
  {
    id: 'secret-1password-service-token',
    name: '1Password Service Account Token',
    description: '1Password service account token detected',
    severity: 'critical',
    category: 'identity',
    pattern: /\bops_eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b/g,
    recommendation: 'Revoke this 1Password service account token at 1password.com.',
    falsePositiveFilter: fp,
  },

  // Vault (HashiCorp) - additional patterns
  {
    id: 'secret-vault-app-role-secret',
    name: 'HashiCorp Vault AppRole Secret ID',
    description: 'Vault AppRole secret ID detected',
    severity: 'high',
    category: 'identity',
    pattern: /(?:vault)[_\-.]?(?:app[_\-.]?role[_\-.]?)?secret[_\-.]?id\s*[=:'"]+\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?/gi,
    recommendation: 'Rotate this Vault AppRole secret ID.',
    falsePositiveFilter: fp,
  },

  // Duo Security
  {
    id: 'secret-duo-secret-key',
    name: 'Duo Security Secret Key',
    description: 'Duo Security API secret key detected',
    severity: 'critical',
    category: 'identity',
    pattern: /(?:duo)[_\-.]?(?:secret|skey)[_\-.]?key\s*[=:'"]+\s*['"]?([A-Za-z0-9]{40})['"]?/gi,
    recommendation: 'Rotate this Duo secret key at admin.duosecurity.com.',
    falsePositiveFilter: fp,
  },

  // Vercel
  {
    id: 'secret-vercel-token',
    name: 'Vercel Access Token',
    description: 'Vercel deployment access token detected',
    severity: 'critical',
    category: 'identity',
    pattern: /(?:vercel)[_\-.]?(?:access[_\-.]?)?token\s*[=:'"]+\s*['"]?([a-zA-Z0-9]{24})['"]?/gi,
    recommendation: 'Rotate this Vercel token at vercel.com/account/tokens.',
    falsePositiveFilter: fp,
  },

  // Netlify
  {
    id: 'secret-netlify-token',
    name: 'Netlify Access Token',
    description: 'Netlify personal access token detected',
    severity: 'high',
    category: 'identity',
    pattern: /(?:netlify)[_\-.]?(?:access[_\-.]?)?token\s*[=:'"]+\s*['"]?([a-zA-Z0-9_\-]{43,})['"]?/gi,
    recommendation: 'Rotate this Netlify token at app.netlify.com/user/applications.',
    falsePositiveFilter: fp,
  },
];
