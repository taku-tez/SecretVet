import type { SecretRule } from '../types.js';

const PLACEHOLDER_RE = /your[_-]?(api[_-]?)?key|example|dummy|placeholder|xxx+|test[_-]?key|fake|sample|changeme|\*{4,}/i;
const fp = (match: string) => PLACEHOLDER_RE.test(match);

export const rules: SecretRule[] = [
  // PagerDuty
  {
    id: 'secret-pagerduty-api-key',
    name: 'PagerDuty API Key',
    description: 'PagerDuty API key detected',
    severity: 'high',
    category: 'collaboration',
    pattern: /(?:pagerduty|pd)[_\-.]?(?:api[_\-.]?)?(?:key|token)\s*[=:'"]+\s*['"]?([a-zA-Z0-9+/=_\-]{20,})['"]?/gi,
    recommendation: 'Rotate this PagerDuty API key at app.pagerduty.com/api_keys.',
    falsePositiveFilter: fp,
  },

  // Opsgenie
  {
    id: 'secret-opsgenie-api-key',
    name: 'Opsgenie API Key',
    description: 'Opsgenie alert integration API key detected',
    severity: 'high',
    category: 'collaboration',
    pattern: /(?:opsgenie)[_\-.]?(?:api[_\-.]?)?(?:key|token)\s*[=:'"]+\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?/gi,
    recommendation: 'Rotate this Opsgenie API key in your integration settings.',
    falsePositiveFilter: fp,
  },

  // Linear
  {
    id: 'secret-linear-api-key',
    name: 'Linear API Key',
    description: 'Linear project management API key detected',
    severity: 'high',
    category: 'collaboration',
    pattern: /\blin_api_[a-zA-Z0-9]{40}\b/g,
    recommendation: 'Rotate this Linear API key at linear.app/settings/api.',
    falsePositiveFilter: fp,
  },

  // Zendesk
  {
    id: 'secret-zendesk-api-token',
    name: 'Zendesk API Token',
    description: 'Zendesk support API token detected',
    severity: 'high',
    category: 'collaboration',
    pattern: /(?:zendesk)[_\-.]?(?:api[_\-.]?)?token\s*[=:'"]+\s*['"]?([A-Za-z0-9]{40})['"]?/gi,
    recommendation: 'Rotate this Zendesk API token in Admin > Channels > API.',
    falsePositiveFilter: fp,
  },

  // Intercom
  {
    id: 'secret-intercom-access-token',
    name: 'Intercom Access Token',
    description: 'Intercom customer messaging access token detected',
    severity: 'high',
    category: 'collaboration',
    pattern: /(?:intercom)[_\-.]?(?:access[_\-.]?)?token\s*[=:'"]+\s*['"]?([a-zA-Z0-9_\-]{60,})['"]?/gi,
    recommendation: 'Rotate this Intercom token at app.intercom.com/developers.',
    falsePositiveFilter: fp,
  },

  // Notion
  {
    id: 'secret-notion-integration-token',
    name: 'Notion Integration Token',
    description: 'Notion integration secret token detected',
    severity: 'high',
    category: 'collaboration',
    pattern: /\bsecret_[a-zA-Z0-9]{43}\b/g,
    recommendation: 'Rotate this Notion integration token at notion.so/my-integrations.',
    falsePositiveFilter: fp,
  },

  // Airtable
  {
    id: 'secret-airtable-api-key',
    name: 'Airtable API Key',
    description: 'Airtable personal access token or legacy API key detected',
    severity: 'high',
    category: 'collaboration',
    pattern: /\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b|\b(?:airtable)[_\-.]?(?:api[_\-.]?)?key\s*[=:'"]+\s*['"]?(key[a-zA-Z0-9]{14})['"]?/gi,
    recommendation: 'Rotate this Airtable token at airtable.com/create/tokens.',
    falsePositiveFilter: fp,
  },

  // Microsoft Teams
  {
    id: 'secret-ms-teams-webhook',
    name: 'Microsoft Teams Webhook URL',
    description: 'Microsoft Teams incoming webhook URL detected',
    severity: 'medium',
    category: 'collaboration',
    pattern: /https:\/\/[a-zA-Z0-9]+\.webhook\.office\.com\/webhookb2\/[a-f0-9\-]+@[a-f0-9\-]+\/IncomingWebhook\/[a-f0-9]+\/[a-f0-9\-]+/gi,
    recommendation: 'Remove this Teams webhook URL and create a new one if needed.',
  },

  // Jira / Atlassian
  {
    id: 'secret-atlassian-api-token',
    name: 'Atlassian API Token',
    description: 'Atlassian (Jira/Confluence) API token detected',
    severity: 'high',
    category: 'collaboration',
    pattern: /(?:atlassian|jira|confluence)[_\-.]?(?:api[_\-.]?)?token\s*[=:'"]+\s*['"]?([A-Za-z0-9]{24,})['"]?/gi,
    recommendation: 'Rotate this Atlassian API token at id.atlassian.com/manage-profile/security/api-tokens.',
    falsePositiveFilter: fp,
  },
];
