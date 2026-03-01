import * as fs from 'fs';
import * as path from 'path';
import type { Severity } from './types.js';

export interface RuleConfig {
  id: string;
  name?: string;
  description?: string;
  severity?: Severity;
  category?: string;
  pattern: string;
  recommendation?: string;
  falsePositiveRegexes?: string[];
}

export interface AllowlistConfig {
  description?: string;
  commits?: string[];
  files?: string[];
  paths?: string[];
  regexes?: string[];
}

export interface RuleAllowlist {
  ruleId: string;
  paths?: string[];
  regexes?: string[];
}

export interface SecretVetConfig {
  config?: {
    minSeverity?: Severity;
    entropy?: boolean;
    entropyThreshold?: number;
    skipTests?: boolean;
    maxFileSize?: number;
  };
  extend?: {
    useDefault?: boolean;
    disableRules?: string[];
  };
  rules?: RuleConfig[];
  allowlist?: AllowlistConfig;
  ruleAllowlists?: RuleAllowlist[];
}

const CONFIG_FILES = ['.secretvetrc.json', '.secretvetrc', 'secretvet.config.json'];

export function loadConfig(cwd: string = process.cwd()): SecretVetConfig | null {
  for (const filename of CONFIG_FILES) {
    const fullPath = path.join(cwd, filename);
    if (fs.existsSync(fullPath)) {
      try {
        const raw = fs.readFileSync(fullPath, 'utf-8');
        return JSON.parse(raw) as SecretVetConfig;
      } catch (err) {
        throw new Error(`Failed to parse ${filename}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  }
  return null;
}

export function resolveConfigPath(cwd: string = process.cwd()): string | null {
  for (const filename of CONFIG_FILES) {
    const fullPath = path.join(cwd, filename);
    if (fs.existsSync(fullPath)) return fullPath;
  }
  return null;
}

export function mergeConfigWithOptions(
  config: SecretVetConfig | null,
  cliOptions: Record<string, unknown>
): Record<string, unknown> {
  if (!config?.config) return cliOptions;
  const merged: Record<string, unknown> = { ...cliOptions };
  const c = config.config;
  if (c.minSeverity && !cliOptions['min-severity']) merged['minSeverity'] = c.minSeverity;
  if (c.entropy !== undefined && cliOptions['entropy'] === undefined) merged['entropy'] = c.entropy;
  if (c.entropyThreshold !== undefined && !cliOptions['entropyThreshold']) merged['entropyThreshold'] = c.entropyThreshold;
  if (c.skipTests && !cliOptions['skip-tests']) merged['skipTests'] = true;
  if (c.maxFileSize !== undefined && !cliOptions['maxFileSize']) merged['maxFileSize'] = c.maxFileSize;
  return merged;
}

export function buildCustomRules(config: SecretVetConfig | null) {
  if (!config?.rules?.length) return [];

  return config.rules.map(r => {
    let pattern: RegExp;
    try {
      pattern = new RegExp(r.pattern, 'g');
    } catch {
      throw new Error(`Invalid regex in custom rule ${r.id}: ${r.pattern}`);
    }

    const fpRegexes = (r.falsePositiveRegexes ?? []).map(re => new RegExp(re, 'i'));

    return {
      id: r.id,
      name: r.name ?? r.id,
      description: r.description ?? `Custom rule: ${r.id}`,
      severity: r.severity ?? 'high' as Severity,
      category: r.category ?? 'custom',
      pattern,
      recommendation: r.recommendation ?? 'Review and remove this secret.',
      falsePositiveFilter: fpRegexes.length > 0
        ? (match: string) => fpRegexes.some(re => re.test(match))
        : undefined,
    };
  });
}

export function buildAllowlistMatcher(config: SecretVetConfig | null) {
  if (!config?.allowlist) return null;

  const al = config.allowlist;
  const fileRegexes = (al.files ?? []).map(f => new RegExp(f, 'i'));
  const pathRegexes = (al.paths ?? []).map(p => new RegExp(p, 'i'));
  const valueRegexes = (al.regexes ?? []).map(r => new RegExp(r, 'i'));
  const commitSet = new Set(al.commits ?? []);

  return {
    isCommitAllowed: (commit: string) => commitSet.has(commit),
    isFileAllowed: (filePath: string) => {
      const basename = filePath.split('/').pop() ?? filePath;
      return fileRegexes.some(re => re.test(basename)) ||
             pathRegexes.some(re => re.test(filePath));
    },
    isMatchAllowed: (match: string) => valueRegexes.some(re => re.test(match)),
  };
}

export const CONFIG_SCHEMA_EXAMPLE: SecretVetConfig = {
  config: {
    minSeverity: 'medium',
    entropy: true,
    entropyThreshold: 4.0,
    skipTests: false,
  },
  extend: {
    useDefault: true,
    disableRules: ['secret-jwt-token', 'secret-high-entropy-string'],
  },
  rules: [
    {
      id: 'custom-internal-api-key',
      name: 'Internal API Key',
      description: 'Company internal API key detected',
      severity: 'critical',
      category: 'custom',
      pattern: 'corp_[a-zA-Z0-9]{32}',
      recommendation: 'Use vault to store internal keys',
      falsePositiveRegexes: ['EXAMPLE', 'TEST', 'DUMMY'],
    },
  ],
  allowlist: {
    description: 'Global allowlist',
    commits: [],
    files: ['go\\.sum', 'package-lock\\.json', 'yarn\\.lock'],
    paths: ['test/fixtures/', 'docs/'],
    regexes: ['EXAMPLE_KEY', 'YOUR_API_KEY', 'INSERT_HERE'],
  },
  ruleAllowlists: [
    {
      ruleId: 'secret-jwt-token',
      paths: ['test/', 'spec/'],
    },
  ],
};
