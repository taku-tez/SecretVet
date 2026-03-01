import type { SecretRule } from '../types.js';

const PLACEHOLDER_RE = /your[_-]?(api[_-]?)?key|example|dummy|placeholder|xxx+|test[_-]?key|fake|sample|changeme|\*{4,}/i;
const fp = (match: string) => PLACEHOLDER_RE.test(match);

export const rules: SecretRule[] = [
  // Datadog
  {
    id: 'secret-datadog-api-key',
    name: 'Datadog API Key',
    description: 'Datadog API key detected',
    severity: 'critical',
    category: 'monitoring',
    pattern: /(?:datadog|DD)[_\-.]?(?:api[_\-.]?)?key\s*[=:'"]+\s*['"]?([a-f0-9]{32})['"]?/gi,
    recommendation: 'Rotate this Datadog API key at app.datadoghq.com/organization-settings/api-keys.',
    falsePositiveFilter: fp,
  },
  {
    id: 'secret-datadog-app-key',
    name: 'Datadog Application Key',
    description: 'Datadog application key detected',
    severity: 'high',
    category: 'monitoring',
    pattern: /(?:datadog|DD)[_\-.]?app(?:lication)?[_\-.]?key\s*[=:'"]+\s*['"]?([a-f0-9]{40})['"]?/gi,
    recommendation: 'Rotate this Datadog app key.',
    falsePositiveFilter: fp,
  },

  // New Relic
  {
    id: 'secret-newrelic-license-key',
    name: 'New Relic License Key',
    description: 'New Relic license key detected',
    severity: 'critical',
    category: 'monitoring',
    pattern: /(?:new[_\-.]?relic|NR)[_\-.]?(?:license|ingest|api)[_\-.]?key\s*[=:'"]+\s*['"]?([A-Za-z0-9]{32,40})['"]?/gi,
    recommendation: 'Rotate this New Relic license key at one.newrelic.com.',
    falsePositiveFilter: fp,
  },
  {
    id: 'secret-newrelic-user-key',
    name: 'New Relic User API Key',
    description: 'New Relic user API key detected',
    severity: 'high',
    category: 'monitoring',
    pattern: /\bNRAK-[A-Z0-9]{27}\b/g,
    recommendation: 'Rotate this New Relic user key.',
    falsePositiveFilter: fp,
  },

  // Sentry
  {
    id: 'secret-sentry-auth-token',
    name: 'Sentry Auth Token',
    description: 'Sentry authentication token detected',
    severity: 'high',
    category: 'monitoring',
    pattern: /(?:sentry)[_\-.]?(?:auth[_\-.]?)?token\s*[=:'"]+\s*['"]?([a-f0-9]{64})['"]?/gi,
    recommendation: 'Rotate this Sentry token at sentry.io/settings/account/api/auth-tokens/.',
    falsePositiveFilter: fp,
  },
  {
    id: 'secret-sentry-dsn',
    name: 'Sentry DSN',
    description: 'Sentry DSN with secret key component detected',
    severity: 'medium',
    category: 'monitoring',
    pattern: /https?:\/\/[a-f0-9]{32}@(?:[a-z0-9]+\.)*sentry\.io\/\d+/gi,
    recommendation: 'Sentry DSNs in client code are expected, but server-side DSNs should be protected.',
  },

  // Splunk
  {
    id: 'secret-splunk-hec-token',
    name: 'Splunk HEC Token',
    description: 'Splunk HTTP Event Collector token detected',
    severity: 'high',
    category: 'monitoring',
    pattern: /(?:splunk)[_\-.]?(?:hec[_\-.]?)?token\s*[=:'"]+\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?/gi,
    recommendation: 'Rotate this Splunk HEC token in Splunk settings.',
    falsePositiveFilter: fp,
  },

  // Grafana
  {
    id: 'secret-grafana-service-token',
    name: 'Grafana Service Account Token',
    description: 'Grafana service account token detected',
    severity: 'high',
    category: 'monitoring',
    pattern: /\bglsa_[a-zA-Z0-9]{32}_[a-f0-9]{8}\b/g,
    recommendation: 'Rotate this Grafana service account token.',
    falsePositiveFilter: fp,
  },
  {
    id: 'secret-grafana-api-key',
    name: 'Grafana API Key (legacy)',
    description: 'Grafana legacy API key detected',
    severity: 'high',
    category: 'monitoring',
    pattern: /(?:grafana)[_\-.]?(?:api[_\-.]?)?(?:key|token)\s*[=:'"]+\s*['"]?(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)['"]?/gi,
    recommendation: 'Migrate to Grafana service account tokens and rotate this key.',
    falsePositiveFilter: fp,
  },

  // Honeycomb
  {
    id: 'secret-honeycomb-api-key',
    name: 'Honeycomb API Key',
    description: 'Honeycomb observability API key detected',
    severity: 'high',
    category: 'monitoring',
    pattern: /(?:honeycomb)[_\-.]?(?:api[_\-.]?)?(?:key|token)\s*[=:'"]+\s*['"]?([a-zA-Z0-9]{32})['"]?/gi,
    recommendation: 'Rotate this Honeycomb API key at ui.honeycomb.io/account.',
    falsePositiveFilter: fp,
  },

  // Segment
  {
    id: 'secret-segment-write-key',
    name: 'Segment Write Key',
    description: 'Segment analytics write key detected',
    severity: 'medium',
    category: 'monitoring',
    pattern: /(?:segment)[_\-.]?(?:write[_\-.]?)?key\s*[=:'"]+\s*['"]?([A-Za-z0-9]{32,})['"]?/gi,
    recommendation: 'Rotate this Segment write key in your workspace settings.',
    falsePositiveFilter: fp,
  },

  // Amplitude
  {
    id: 'secret-amplitude-api-key',
    name: 'Amplitude API Key',
    description: 'Amplitude analytics API key detected',
    severity: 'medium',
    category: 'monitoring',
    pattern: /(?:amplitude)[_\-.]?(?:api[_\-.]?)?key\s*[=:'"]+\s*['"]?([a-f0-9]{32})['"]?/gi,
    recommendation: 'Rotate this Amplitude API key.',
    falsePositiveFilter: fp,
  },
];
