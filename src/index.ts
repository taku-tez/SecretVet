export { scan, scanFile } from './scanner.js';
export { formatOutput, formatText, formatJson, formatSarif } from './reporter.js';
export { ALL_RULES, getRulesByCategory, getRuleById, CATEGORIES } from './rules/index.js';
export type { SecretRule, SecretFinding, ScanResult, ScanOptions, Severity } from './types.js';
export { shannonEntropy } from './rules/generic.js';
