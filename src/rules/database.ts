import type { SecretRule } from '../types.js';

const PLACEHOLDER_RE = /your[_-]?(api[_-]?)?key|example|dummy|placeholder|xxx+|test[_-]?key|fake|sample|changeme|\*{4,}|localhost|127\.0\.0\.1/i;

function isPlaceholder(match: string): boolean {
  return PLACEHOLDER_RE.test(match);
}

export const rules: SecretRule[] = [
  {
    id: 'secret-mongodb-atlas-url',
    name: 'MongoDB Atlas Connection String',
    description: 'MongoDB Atlas connection string with credentials detected',
    severity: 'critical',
    category: 'database',
    pattern: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[a-zA-Z0-9.-]+\.mongodb\.net/gi,
    recommendation: 'Use environment variables for database credentials. Rotate MongoDB Atlas user password.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-postgres-url',
    name: 'PostgreSQL Connection String',
    description: 'PostgreSQL connection string with credentials detected',
    severity: 'high',
    category: 'database',
    pattern: /postgres(?:ql)?:\/\/[^:]+:[^@\s'"]+@[^/\s'"]{4,}/gi,
    recommendation: 'Use environment variables for database credentials.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-mysql-url',
    name: 'MySQL Connection String',
    description: 'MySQL connection string with credentials detected',
    severity: 'high',
    category: 'database',
    pattern: /mysql(?:2)?:\/\/[^:]+:[^@\s'"]+@[^/\s'"]{4,}/gi,
    recommendation: 'Use environment variables for database credentials.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-redis-url',
    name: 'Redis Connection String',
    description: 'Redis connection string with password detected',
    severity: 'medium',
    category: 'database',
    pattern: /redis(?:s)?:\/\/(?:[^:]+:)?[^@\s'"]{8,}@[^/\s'"]{4,}/gi,
    recommendation: 'Use environment variables for Redis credentials.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-elasticsearch-url',
    name: 'Elasticsearch Connection String',
    description: 'Elasticsearch URL with credentials detected',
    severity: 'high',
    category: 'database',
    pattern: /https?:\/\/[^:]+:[^@\s'"]{8,}@[^/\s'"]{4,}(?:9200|9243|elastic)/gi,
    recommendation: 'Use environment variables for Elasticsearch credentials.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-cassandra-password',
    name: 'Cassandra Password',
    description: 'Cassandra database password detected in context',
    severity: 'high',
    category: 'database',
    pattern: /(?:cassandra|CASSANDRA)[_\-.]?(?:password|passwd|secret)\s*[=:'"]+\s*['"]?([A-Za-z0-9!@#$%^&*]{8,})['"]?/gi,
    recommendation: 'Use environment variables for Cassandra credentials.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-planetscale-password',
    name: 'PlanetScale Database Password',
    description: 'PlanetScale database URL with credentials detected',
    severity: 'critical',
    category: 'database',
    pattern: /mysql:\/\/[^:]+:[^@\s'"]{8,}@[^/\s'"]*\.psdb\.cloud/gi,
    recommendation: 'Rotate PlanetScale database password in the dashboard.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-supabase-key',
    name: 'Supabase API Key',
    description: 'Supabase service role or anon key detected',
    severity: 'critical',
    category: 'database',
    pattern: /(?:supabase)[_\-.]?(?:service[_\-.]?role|anon|api)[_\-.]?(?:key|secret)\s*[=:'"]+\s*['"]?(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)['"]?/gi,
    recommendation: 'Rotate Supabase keys in the project settings. Service role keys should never be in frontend code.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
];
