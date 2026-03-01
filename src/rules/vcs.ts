import type { SecretRule } from '../types.js';

const PLACEHOLDER_RE = /your[_-]?(api[_-]?)?key|example|dummy|placeholder|xxx+|test[_-]?key|fake|sample|changeme|\*{4,}/i;

function isPlaceholder(match: string): boolean {
  return PLACEHOLDER_RE.test(match);
}

export const rules: SecretRule[] = [
  // GitHub
  {
    id: 'secret-github-pat',
    name: 'GitHub Personal Access Token',
    description: 'GitHub classic personal access token detected',
    severity: 'critical',
    category: 'vcs',
    pattern: /\bghp_[a-zA-Z0-9]{36}\b/g,
    recommendation: 'Revoke this token at github.com/settings/tokens.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-github-oauth-token',
    name: 'GitHub OAuth Token',
    description: 'GitHub OAuth access token detected',
    severity: 'critical',
    category: 'vcs',
    pattern: /\bgho_[a-zA-Z0-9]{36}\b/g,
    recommendation: 'Revoke this OAuth token immediately.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-github-user-token',
    name: 'GitHub User-to-Server Token',
    description: 'GitHub user-to-server token detected',
    severity: 'critical',
    category: 'vcs',
    pattern: /\bghu_[a-zA-Z0-9]{36}\b/g,
    recommendation: 'Revoke this GitHub token immediately.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-github-server-token',
    name: 'GitHub Server-to-Server Token',
    description: 'GitHub server-to-server token detected',
    severity: 'critical',
    category: 'vcs',
    pattern: /\bghs_[a-zA-Z0-9]{36}\b/g,
    recommendation: 'Revoke this GitHub token immediately.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-github-refresh-token',
    name: 'GitHub Refresh Token',
    description: 'GitHub OAuth refresh token detected',
    severity: 'critical',
    category: 'vcs',
    pattern: /\bghr_[a-zA-Z0-9]{76}\b/g,
    recommendation: 'Revoke this GitHub refresh token.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-github-fine-grained-pat',
    name: 'GitHub Fine-Grained PAT',
    description: 'GitHub fine-grained personal access token detected',
    severity: 'critical',
    category: 'vcs',
    pattern: /\bgithub_pat_[A-Za-z0-9_]{82}\b/g,
    recommendation: 'Revoke this token at github.com/settings/tokens.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },

  // GitLab
  {
    id: 'secret-gitlab-token',
    name: 'GitLab Personal Access Token',
    description: 'GitLab personal access token detected',
    severity: 'critical',
    category: 'vcs',
    pattern: /\bglpat-[0-9a-zA-Z_\-]{20}\b/g,
    recommendation: 'Revoke this token at gitlab.com/-/profile/personal_access_tokens.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-gitlab-runner-token',
    name: 'GitLab Runner Token',
    description: 'GitLab CI runner registration token detected',
    severity: 'high',
    category: 'vcs',
    pattern: /\bglrt-[0-9a-zA-Z_\-]{20}\b/g,
    recommendation: 'Revoke this runner token in GitLab CI settings.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },

  // Bitbucket
  {
    id: 'secret-bitbucket-token',
    name: 'Bitbucket App Password',
    description: 'Bitbucket app password or access token detected',
    severity: 'high',
    category: 'vcs',
    pattern: /(?:bitbucket)[_\-.]?(?:app[_\-.]?)?(?:password|token|secret)\s*[=:'"]+\s*['"]?([A-Za-z0-9]{32,})['"]?/gi,
    recommendation: 'Revoke this Bitbucket app password in account settings.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
];
