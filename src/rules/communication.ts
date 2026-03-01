import type { SecretRule } from '../types.js';

const PLACEHOLDER_RE = /your[_-]?(api[_-]?)?key|example|dummy|placeholder|xxx+|test[_-]?key|fake|sample|changeme|\*{4,}/i;

function isPlaceholder(match: string): boolean {
  return PLACEHOLDER_RE.test(match);
}

export const rules: SecretRule[] = [
  // Twilio
  {
    id: 'secret-twilio-account-sid',
    name: 'Twilio Account SID',
    description: 'Twilio Account SID detected',
    severity: 'high',
    category: 'communication',
    pattern: /\bAC[a-f0-9]{32}\b/g,
    recommendation: 'Rotate Twilio credentials at console.twilio.com.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-twilio-auth-token',
    name: 'Twilio Auth Token',
    description: 'Twilio Auth Token detected (context-based)',
    severity: 'critical',
    category: 'communication',
    pattern: /(?:twilio)[_\-.]?(?:auth[_\-.]?)?(?:token|secret)\s*[=:'"]+\s*['"]?([a-f0-9]{32})['"]?/gi,
    recommendation: 'Rotate this Twilio auth token immediately.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },

  // SendGrid
  {
    id: 'secret-sendgrid-key',
    name: 'SendGrid API Key',
    description: 'SendGrid API key detected',
    severity: 'high',
    category: 'communication',
    pattern: /\bSG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}\b/g,
    recommendation: 'Rotate this SendGrid API key at app.sendgrid.com.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },

  // Mailgun
  {
    id: 'secret-mailgun-key',
    name: 'Mailgun API Key',
    description: 'Mailgun API key detected',
    severity: 'high',
    category: 'communication',
    pattern: /\bkey-[0-9a-zA-Z]{32}\b/g,
    recommendation: 'Rotate this Mailgun key at app.mailgun.com.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-mailgun-private-key',
    name: 'Mailgun Private API Key',
    description: 'Mailgun private API key detected',
    severity: 'critical',
    category: 'communication',
    pattern: /(?:mailgun)[_\-.]?(?:private[_\-.]?)?(?:api[_\-.]?)?(?:key|secret)\s*[=:'"]+\s*['"]?(key-[0-9a-zA-Z]{32})['"]?/gi,
    recommendation: 'Rotate this Mailgun key immediately.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },

  // Slack
  {
    id: 'secret-slack-token',
    name: 'Slack Token',
    description: 'Slack API token detected',
    severity: 'critical',
    category: 'communication',
    pattern: /\bxox[baprs]-(?:[0-9a-zA-Z]{10,48}-?)+\b/g,
    recommendation: 'Rotate this Slack token at api.slack.com/apps.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-slack-webhook',
    name: 'Slack Webhook URL',
    description: 'Slack incoming webhook URL detected',
    severity: 'high',
    category: 'communication',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g,
    recommendation: 'Revoke this webhook URL in your Slack app settings.',
  },
  {
    id: 'secret-slack-signing-secret',
    name: 'Slack Signing Secret',
    description: 'Slack app signing secret detected',
    severity: 'high',
    category: 'communication',
    pattern: /(?:slack)[_\-.]?(?:signing[_\-.]?)?secret\s*[=:'"]+\s*['"]?([a-f0-9]{32})['"]?/gi,
    recommendation: 'Rotate this Slack signing secret in your app settings.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },

  // Discord
  {
    id: 'secret-discord-webhook',
    name: 'Discord Webhook URL',
    description: 'Discord incoming webhook URL detected',
    severity: 'medium',
    category: 'communication',
    pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_\-]+/g,
    recommendation: 'Delete this webhook in Discord server settings and create a new one.',
  },
  {
    id: 'secret-discord-bot-token',
    name: 'Discord Bot Token',
    description: 'Discord bot token detected',
    severity: 'critical',
    category: 'communication',
    pattern: /\b[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9_\-]{6}\.[a-zA-Z0-9_\-]{27,38}\b/g,
    recommendation: 'Reset this Discord bot token at discord.com/developers.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },

  // Telegram
  {
    id: 'secret-telegram-bot-token',
    name: 'Telegram Bot Token',
    description: 'Telegram bot API token detected',
    severity: 'high',
    category: 'communication',
    pattern: /\b\d{9,10}:[a-zA-Z0-9_\-]{35}\b/g,
    recommendation: 'Revoke this Telegram bot token via @BotFather.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },

  // Mailchimp
  {
    id: 'secret-mailchimp-key',
    name: 'Mailchimp API Key',
    description: 'Mailchimp API key detected',
    severity: 'high',
    category: 'communication',
    pattern: /\b[a-f0-9]{32}-us\d+\b/g,
    recommendation: 'Rotate this Mailchimp API key in your account.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
];
