import type { SecretRule } from '../types.js';

const PLACEHOLDER_RE = /your[_-]?(api[_-]?)?key|example|dummy|placeholder|xxx+|test[_-]?key|fake|sample|changeme|replace[_-]?me|\*{4,}|0{8,}/i;

function isPlaceholder(match: string): boolean {
  return PLACEHOLDER_RE.test(match);
}

export const rules: SecretRule[] = [
  // AWS
  {
    id: 'secret-aws-access-key',
    name: 'AWS Access Key ID',
    description: 'AWS Access Key ID detected',
    severity: 'critical',
    category: 'cloud',
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    recommendation: 'Use environment variables or AWS credentials file (~/.aws/credentials). Rotate this key immediately.',
    references: ['https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html'],
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-aws-secret-key',
    name: 'AWS Secret Access Key',
    description: 'AWS Secret Access Key detected (context-based)',
    severity: 'critical',
    category: 'cloud',
    pattern: /(?:aws[_\-.]?secret|secret[_\-.]?access[_\-.]?key|AWS_SECRET_ACCESS_KEY|secretAccessKey)\s*[=:'"]+\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    recommendation: 'Use environment variables or AWS credentials file. Rotate this key immediately.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-aws-session-token',
    name: 'AWS Session Token',
    description: 'AWS temporary session token detected',
    severity: 'critical',
    category: 'cloud',
    pattern: /\bASIA[0-9A-Z]{16}\b/g,
    recommendation: 'Temporary credentials should not be committed. Use IAM roles instead.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-aws-mws-key',
    name: 'AWS MWS Key',
    description: 'Amazon MWS authentication token detected',
    severity: 'high',
    category: 'cloud',
    pattern: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
    recommendation: 'Rotate this MWS key immediately and use environment variables.',
  },

  // GCP
  {
    id: 'secret-gcp-api-key',
    name: 'Google Cloud API Key',
    description: 'Google Cloud Platform API key detected',
    severity: 'critical',
    category: 'cloud',
    pattern: /\bAIza[0-9A-Za-z_\-]{35}\b/g,
    recommendation: 'Restrict this API key in the GCP Console and use service accounts instead.',
    references: ['https://cloud.google.com/docs/authentication/api-keys'],
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-gcp-service-account',
    name: 'GCP Service Account Key',
    description: 'GCP service account key file contents detected',
    severity: 'critical',
    category: 'cloud',
    pattern: /"type"\s*:\s*"service_account"[\s\S]{0,500}"private_key"/g,
    recommendation: 'Use Workload Identity Federation or managed service accounts. Never commit service account JSON.',
  },
  {
    id: 'secret-gcp-oauth-token',
    name: 'Google OAuth Token',
    description: 'Google OAuth access token detected',
    severity: 'high',
    category: 'cloud',
    pattern: /ya29\.[0-9A-Za-z_\-]{68,}/g,
    recommendation: 'OAuth tokens are short-lived but should not be committed. Use environment variables.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },

  // Azure
  {
    id: 'secret-azure-connection-string',
    name: 'Azure Connection String',
    description: 'Azure storage connection string detected',
    severity: 'critical',
    category: 'cloud',
    pattern: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}/gi,
    recommendation: 'Use Azure Key Vault or Managed Identity. Rotate the storage account key.',
  },
  {
    id: 'secret-azure-client-secret',
    name: 'Azure Client Secret',
    description: 'Azure Active Directory client secret detected',
    severity: 'critical',
    category: 'cloud',
    pattern: /(?:azure|AZURE)[_\-.]?(?:client[_\-.]?)?(?:secret|password|credential)[_\-.]?\s*[=:'"]+\s*['"]?([A-Za-z0-9~._\-]{34,40})['"]?/gi,
    recommendation: 'Use Azure Key Vault or Managed Identity.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-azure-sas-token',
    name: 'Azure SAS Token',
    description: 'Azure Shared Access Signature token detected',
    severity: 'high',
    category: 'cloud',
    pattern: /(?:sv|se|ss|srt|sp|sig)=[A-Za-z0-9%+/=]+&(?:sv|se|ss|srt|sp|sig)=[A-Za-z0-9%+/=]+/g,
    recommendation: 'SAS tokens grant access to storage resources. Rotate and use short-lived tokens.',
  },

  // Alibaba Cloud
  {
    id: 'secret-alibaba-access-key',
    name: 'Alibaba Cloud Access Key',
    description: 'Alibaba Cloud access key ID detected',
    severity: 'critical',
    category: 'cloud',
    pattern: /\bLTAI[a-zA-Z0-9]{16,24}\b/g,
    recommendation: 'Rotate this Alibaba Cloud access key and use RAM roles instead.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },

  // DigitalOcean
  {
    id: 'secret-digitalocean-token',
    name: 'DigitalOcean Token',
    description: 'DigitalOcean personal access token detected',
    severity: 'critical',
    category: 'cloud',
    pattern: /(?:digitalocean|do)[_\-.]?(?:api[_\-.]?)?token\s*[=:'"]+\s*['"]?([a-f0-9]{64})['"]?/gi,
    recommendation: 'Rotate this DigitalOcean token in the control panel.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },

  // Cloudflare
  {
    id: 'secret-cloudflare-api-key',
    name: 'Cloudflare API Key',
    description: 'Cloudflare API key detected',
    severity: 'critical',
    category: 'cloud',
    pattern: /(?:cloudflare|cf)[_\-.]?(?:api[_\-.]?)?(?:key|token)\s*[=:'"]+\s*['"]?([A-Za-z0-9_\-]{37,40})['"]?/gi,
    recommendation: 'Use scoped API tokens instead of global API keys.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-cloudflare-global-api-key',
    name: 'Cloudflare Global API Key',
    description: 'Cloudflare global API key pattern detected (40 char hex)',
    severity: 'critical',
    category: 'cloud',
    pattern: /(?:X-Auth-Key|CF_API_KEY)\s*[=:'"]+\s*['"]?([a-f0-9]{37})['"]?/gi,
    recommendation: 'Replace with scoped Cloudflare API tokens.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
];
