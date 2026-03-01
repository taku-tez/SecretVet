export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SecretRule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: string;
  pattern: RegExp;
  recommendation: string;
  references?: string[];
  falsePositiveFilter?: (match: string, lineContext: string) => boolean;
}

export interface SecretFinding {
  id: string;
  ruleId: string;
  ruleName: string;
  description: string;
  severity: Severity;
  category: string;
  file: string;
  line: number;
  column: number;
  match: string;
  context: string;
  recommendation: string;
}

export interface ScanResult {
  target: string;
  timestamp: string;
  duration: number;
  filesScanned: number;
  filesSkipped: number;
  findings: SecretFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  version: string;
  errors: Array<{ file: string; error: string }>;
}

export interface ScanOptions {
  ignore?: string[];
  ignoreFile?: string;
  maxFileSize?: number;
  format?: 'text' | 'json' | 'sarif';
  minSeverity?: Severity;
  verbose?: boolean;
  showSecrets?: boolean;
  skipTests?: boolean;
  entropy?: boolean;
  entropyThreshold?: number;
  workers?: number;
}
