import { rules as cloudRules } from './cloud.js';
import { rules as cloudSaasRules } from './cloud-saas.js';
import { rules as aiRules } from './ai.js';
import { rules as paymentRules } from './payment.js';
import { rules as communicationRules } from './communication.js';
import { rules as vcsRules } from './vcs.js';
import { rules as databaseRules } from './database.js';
import { rules as authRules } from './auth.js';
import { rules as cicdRules } from './cicd.js';
import { rules as monitoringRules } from './monitoring.js';
import { rules as collaborationRules } from './collaboration.js';
import { rules as identityRules } from './identity.js';
import { rules as genericRules } from './generic.js';
import type { SecretRule } from '../types.js';

export const ALL_RULES: SecretRule[] = [
  ...cloudRules,
  ...cloudSaasRules,
  ...aiRules,
  ...paymentRules,
  ...communicationRules,
  ...vcsRules,
  ...databaseRules,
  ...authRules,
  ...cicdRules,
  ...monitoringRules,
  ...collaborationRules,
  ...identityRules,
  ...genericRules,
];

export {
  cloudRules, cloudSaasRules, aiRules, paymentRules, communicationRules,
  vcsRules, databaseRules, authRules, cicdRules,
  monitoringRules, collaborationRules, identityRules, genericRules,
};

export function getRulesByCategory(category: string): SecretRule[] {
  return ALL_RULES.filter(r => r.category === category);
}

export function getRuleById(id: string): SecretRule | undefined {
  return ALL_RULES.find(r => r.id === id);
}

export const CATEGORIES = [
  'cloud', 'cloud-saas', 'ai', 'payment', 'communication',
  'vcs', 'database', 'auth', 'cicd', 'monitoring', 'collaboration', 'identity', 'generic',
] as const;
export type Category = typeof CATEGORIES[number];
