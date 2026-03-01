import type { SecretRule } from '../types.js';

const PLACEHOLDER_RE = /your[_-]?(api[_-]?)?key|example|dummy|placeholder|xxx+|test[_-]?key|fake|sample|changeme|\*{4,}/i;
const fp = (match: string) => PLACEHOLDER_RE.test(match);

export const rules: SecretRule[] = [
  // Firebase
  {
    id: 'secret-firebase-api-key',
    name: 'Firebase API Key',
    description: 'Firebase web API key detected',
    severity: 'medium',
    category: 'cloud-saas',
    pattern: /(?:firebase|FIREBASE)[_\-.]?(?:api[_\-.]?)?key\s*[=:'"]+\s*['"]?(AIza[0-9A-Za-z_\-]{35})['"]?/gi,
    recommendation: 'Firebase API keys are restricted by domain/app rules, but should still be protected. Review Firebase security rules.',
    falsePositiveFilter: fp,
  },
  {
    id: 'secret-firebase-service-account',
    name: 'Firebase Service Account',
    description: 'Firebase service account private key detected',
    severity: 'critical',
    category: 'cloud-saas',
    pattern: /"type"\s*:\s*"service_account"[\s\S]{0,200}"project_id"[\s\S]{0,500}"private_key"/g,
    recommendation: 'Never commit Firebase service account keys. Use environment variables or Secret Manager.',
  },
  {
    id: 'secret-firebase-admin-token',
    name: 'Firebase Admin SDK Credential',
    description: 'Firebase Admin SDK credential detected',
    severity: 'critical',
    category: 'cloud-saas',
    pattern: /(?:firebase[_\-.]?admin|FIREBASE_ADMIN)[_\-.]?(?:private[_\-.]?key|credential)\s*[=:'"]+\s*['"]?([A-Za-z0-9+/=]{100,})['"]?/gi,
    recommendation: 'Rotate Firebase Admin credentials immediately.',
    falsePositiveFilter: fp,
  },

  // Shopify
  {
    id: 'secret-shopify-private-app-password',
    name: 'Shopify Private App Password',
    description: 'Shopify private app password or Admin API access token detected',
    severity: 'critical',
    category: 'cloud-saas',
    pattern: /\bshppa_[a-fA-F0-9]{32}\b|\bshpat_[a-fA-F0-9]{32}\b/g,
    recommendation: 'Rotate this Shopify app token in Partners > Apps.',
    falsePositiveFilter: fp,
  },
  {
    id: 'secret-shopify-shared-secret',
    name: 'Shopify App Shared Secret',
    description: 'Shopify app shared secret detected',
    severity: 'high',
    category: 'cloud-saas',
    pattern: /(?:shopify)[_\-.]?(?:shared[_\-.]?)?secret\s*[=:'"]+\s*['"]?([a-f0-9]{32})['"]?/gi,
    recommendation: 'Rotate this Shopify shared secret in your app settings.',
    falsePositiveFilter: fp,
  },

  // Fly.io
  {
    id: 'secret-flyio-api-token',
    name: 'Fly.io API Token',
    description: 'Fly.io deployment API token detected',
    severity: 'critical',
    category: 'cloud-saas',
    pattern: /\bFlyV1 [A-Za-z0-9+/=]{100,}\b|\bfly[_\-.]?(?:api[_\-.]?)?token\s*[=:'"]+\s*['"]?(FlyV1 [A-Za-z0-9+/=]{50,})['"]?/gi,
    recommendation: 'Rotate this Fly.io token with: fly tokens create deploy.',
    falsePositiveFilter: fp,
  },

  // Railway
  {
    id: 'secret-railway-token',
    name: 'Railway API Token',
    description: 'Railway deployment token detected',
    severity: 'high',
    category: 'cloud-saas',
    pattern: /(?:railway)[_\-.]?(?:api[_\-.]?)?token\s*[=:'"]+\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?/gi,
    recommendation: 'Rotate this Railway token at railway.app/account/tokens.',
    falsePositiveFilter: fp,
  },

  // Render
  {
    id: 'secret-render-api-key',
    name: 'Render API Key',
    description: 'Render cloud API key detected',
    severity: 'high',
    category: 'cloud-saas',
    pattern: /(?:render)[_\-.]?(?:api[_\-.]?)?key\s*[=:'"]+\s*['"]?(rnd_[a-zA-Z0-9]{32,})['"]?/gi,
    recommendation: 'Rotate this Render API key at dashboard.render.com/u/settings.',
    falsePositiveFilter: fp,
  },

  // Upstash (Redis/QStash)
  {
    id: 'secret-upstash-redis-token',
    name: 'Upstash Redis Token',
    description: 'Upstash serverless Redis token detected',
    severity: 'critical',
    category: 'cloud-saas',
    pattern: /(?:upstash)[_\-.]?(?:redis[_\-.]?)?(?:rest[_\-.]?)?(?:token|password|url)\s*[=:'"]+\s*['"]?([A-Za-z0-9_\-]{40,})['"]?/gi,
    recommendation: 'Rotate this Upstash token at console.upstash.com.',
    falsePositiveFilter: fp,
  },

  // Supabase (additional - service role covered in database.ts)
  {
    id: 'secret-supabase-url-with-key',
    name: 'Supabase URL with embedded key',
    description: 'Supabase project URL with API key in config detected',
    severity: 'high',
    category: 'cloud-saas',
    pattern: /https:\/\/[a-z0-9]+\.supabase\.(?:co|com)[\s\S]{0,100}(?:anon|service)[_\-.]?(?:role[_\-.]?)?key/gi,
    recommendation: 'Keep Supabase URLs and keys in environment variables only.',
  },

  // PlanetScale (additional token types)
  {
    id: 'secret-planetscale-token',
    name: 'PlanetScale Service Token',
    description: 'PlanetScale service token detected',
    severity: 'critical',
    category: 'cloud-saas',
    pattern: /(?:planetscale|pscale)[_\-.]?(?:service[_\-.]?)?token\s*[=:'"]+\s*['"]?(pscale_tkn_[a-zA-Z0-9_]{32,})['"]?/gi,
    recommendation: 'Rotate this PlanetScale token at app.planetscale.com.',
    falsePositiveFilter: fp,
  },
];
