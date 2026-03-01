import type { SecretRule } from '../types.js';

const PLACEHOLDER_RE = /your[_-]?(api[_-]?)?key|example|dummy|placeholder|xxx+|test[_-]?key|fake|sample|changeme|\*{4,}/i;

function isPlaceholder(match: string): boolean {
  return PLACEHOLDER_RE.test(match);
}

export const rules: SecretRule[] = [
  // npm
  {
    id: 'secret-npm-auth-token',
    name: 'npm Auth Token',
    description: 'npm authentication token detected in .npmrc or config',
    severity: 'high',
    category: 'cicd',
    pattern: /(?:_authToken|npm_token|NPM_TOKEN)\s*[=:'"]+\s*['"]?(npm_[a-zA-Z0-9]{36}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?/gi,
    recommendation: 'Revoke this npm token at npmjs.com/settings/tokens. Use CI environment variables.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-npm-granular-token',
    name: 'npm Granular Access Token',
    description: 'npm granular access token detected',
    severity: 'high',
    category: 'cicd',
    pattern: /\bnpm_[a-zA-Z0-9]{36}\b/g,
    recommendation: 'Revoke this npm token at npmjs.com/settings/tokens.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },

  // PyPI
  {
    id: 'secret-pypi-token',
    name: 'PyPI API Token',
    description: 'PyPI package index API token detected',
    severity: 'high',
    category: 'cicd',
    pattern: /\bpypi-[a-zA-Z0-9_\-]{20,}\b/g,
    recommendation: 'Revoke this PyPI token at pypi.org/manage/account/token.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },

  // Docker Hub
  {
    id: 'secret-docker-hub-password',
    name: 'Docker Hub Password',
    description: 'Docker Hub credentials detected',
    severity: 'high',
    category: 'cicd',
    pattern: /(?:docker[_\-.]?(?:hub[_\-.]?)?(?:password|token)|DOCKER_PASSWORD|DOCKERHUB_TOKEN)\s*[=:'"]+\s*['"]?([A-Za-z0-9!@#$%^&*_\-]{8,})['"]?/gi,
    recommendation: 'Use Docker Hub access tokens instead of passwords.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },

  // CircleCI
  {
    id: 'secret-circleci-token',
    name: 'CircleCI API Token',
    description: 'CircleCI personal API token detected',
    severity: 'high',
    category: 'cicd',
    pattern: /(?:circle(?:ci)?)[_\-.]?(?:api[_\-.]?)?token\s*[=:'"]+\s*['"]?([a-f0-9]{40})['"]?/gi,
    recommendation: 'Revoke this CircleCI token at app.circleci.com/settings/user/tokens.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },

  // Travis CI
  {
    id: 'secret-travis-token',
    name: 'Travis CI Token',
    description: 'Travis CI API token detected',
    severity: 'medium',
    category: 'cicd',
    pattern: /(?:travis)[_\-.]?(?:api[_\-.]?)?token\s*[=:'"]+\s*['"]?([A-Za-z0-9_\-]{22})['"]?/gi,
    recommendation: 'Rotate this Travis CI token in your account settings.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },

  // Terraform / HashiCorp
  {
    id: 'secret-terraform-cloud-token',
    name: 'Terraform Cloud Token',
    description: 'Terraform Cloud or HCP Vault token detected',
    severity: 'high',
    category: 'cicd',
    pattern: /\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,}\b/g,
    recommendation: 'Revoke this Terraform Cloud token in your account settings.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },

  // Vault
  {
    id: 'secret-vault-token',
    name: 'HashiCorp Vault Token',
    description: 'HashiCorp Vault token detected',
    severity: 'high',
    category: 'cicd',
    pattern: /\bs\.[a-zA-Z0-9]{24}\b/g,
    recommendation: 'Revoke this Vault token and use dynamic secrets instead.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },

  // Artifactory
  {
    id: 'secret-artifactory-token',
    name: 'JFrog Artifactory Token',
    description: 'JFrog Artifactory API token detected',
    severity: 'high',
    category: 'cicd',
    pattern: /(?:artifactory)[_\-.]?(?:api[_\-.]?)?(?:key|token)\s*[=:'"]+\s*['"]?([A-Za-z0-9]{64})['"]?/gi,
    recommendation: 'Revoke this Artifactory token in the admin panel.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
];
