import type { ScanResult, SecretFinding, Severity } from './types.js';

const c = {
  red: (s: string) => `\x1b[31m${s}\x1b[0m`,
  orange: (s: string) => `\x1b[33m${s}\x1b[0m`,
  yellow: (s: string) => `\x1b[93m${s}\x1b[0m`,
  blue: (s: string) => `\x1b[34m${s}\x1b[0m`,
  gray: (s: string) => `\x1b[90m${s}\x1b[0m`,
  bold: (s: string) => `\x1b[1m${s}\x1b[0m`,
  green: (s: string) => `\x1b[32m${s}\x1b[0m`,
  reset: (s: string) => `\x1b[0m${s}\x1b[0m`,
};

const ICONS: Record<Severity, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
  info: '⚪',
};

function colorBySeverity(severity: Severity, text: string): string {
  switch (severity) {
    case 'critical': return c.red(text);
    case 'high': return c.orange(text);
    case 'medium': return c.yellow(text);
    case 'low': return c.blue(text);
    default: return c.gray(text);
  }
}

export function formatText(result: ScanResult): string {
  const lines: string[] = [];
  lines.push('');
  lines.push(c.bold('🔐 SecretVet Security Scan'));
  lines.push('═'.repeat(52));
  lines.push(`Target:  ${result.target}`);
  lines.push(`Scanned: ${result.filesScanned} files in ${result.duration}ms`);
  lines.push(`Date:    ${result.timestamp}`);
  lines.push('');

  if (result.findings.length === 0) {
    lines.push(c.green('✅ No secrets detected!'));
    lines.push('');
  } else {
    const bySeverity: Record<Severity, SecretFinding[]> = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      info: [],
    };
    for (const f of result.findings) {
      bySeverity[f.severity].push(f);
    }

    for (const sev of ['critical', 'high', 'medium', 'low', 'info'] as Severity[]) {
      const group = bySeverity[sev];
      if (group.length === 0) continue;

      lines.push(colorBySeverity(sev, c.bold(`${ICONS[sev]} ${sev.toUpperCase()} (${group.length})`)));
      lines.push('─'.repeat(40));

      for (const f of group) {
        lines.push(`  ${c.bold(f.ruleName)}`);
        lines.push(`  ${c.gray('File:')} ${f.file}:${f.line}:${f.column}`);
        lines.push(`  ${c.gray('Match:')} ${colorBySeverity(f.severity, f.match)}`);
        lines.push(`  ${c.gray('Context:')}`);
        for (const ctxLine of f.context.split('\n')) {
          lines.push(`    ${c.gray(ctxLine)}`);
        }
        lines.push(`  ${c.gray('→')} ${f.recommendation}`);
        lines.push('');
      }
    }
  }

  const { critical, high, medium, low, info, total } = result.summary;
  lines.push('─'.repeat(52));
  if (total === 0) {
    lines.push(c.green(`📊 Summary: ${c.bold('0 findings')}`));
  } else {
    const parts = [];
    if (critical) parts.push(c.red(`${critical} critical`));
    if (high) parts.push(c.orange(`${high} high`));
    if (medium) parts.push(c.yellow(`${medium} medium`));
    if (low) parts.push(c.blue(`${low} low`));
    if (info) parts.push(c.gray(`${info} info`));
    lines.push(`📊 Summary: ${parts.join(', ')}`);
  }
  lines.push(`   Files scanned: ${result.filesScanned} | Duration: ${result.duration}ms`);

  if (result.errors.length > 0) {
    lines.push('');
    lines.push(c.gray(`⚠️  ${result.errors.length} file(s) had errors during scanning`));
  }

  lines.push('');
  return lines.join('\n');
}

export function formatJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

export function formatSarif(result: ScanResult): string {
  const rules = new Map<string, { id: string; name: string; description: string; recommendation: string }>();
  for (const f of result.findings) {
    if (!rules.has(f.ruleId)) {
      rules.set(f.ruleId, {
        id: f.ruleId,
        name: f.ruleName,
        description: f.description,
        recommendation: f.recommendation,
      });
    }
  }

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'SecretVet',
            version: result.version,
            informationUri: 'https://github.com/taku-tez/SecretVet',
            rules: Array.from(rules.values()).map(r => ({
              id: r.id,
              name: r.name,
              shortDescription: { text: r.description },
              helpUri: 'https://github.com/taku-tez/SecretVet',
              properties: { recommendation: r.recommendation },
            })),
          },
        },
        results: result.findings.map(f => ({
          ruleId: f.ruleId,
          level: f.severity === 'critical' || f.severity === 'high' ? 'error'
            : f.severity === 'medium' ? 'warning' : 'note',
          message: { text: `${f.description}. ${f.recommendation}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file.replace(/\\/g, '/') },
                region: { startLine: f.line, startColumn: f.column },
              },
            },
          ],
          fingerprints: { primaryLocationLineHash: f.id },
        })),
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: result.timestamp,
          },
        ],
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

export function formatOutput(result: ScanResult, format: 'text' | 'json' | 'sarif' = 'text'): string {
  switch (format) {
    case 'json': return formatJson(result);
    case 'sarif': return formatSarif(result);
    default: return formatText(result);
  }
}
