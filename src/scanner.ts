import * as fs from 'fs';
import * as path from 'path';
import * as readline from 'readline';
import { ALL_RULES } from './rules/index.js';
import type { SecretRule, SecretFinding, ScanResult, ScanOptions, Severity } from './types.js';

const VERSION = '0.1.0';

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

const DEFAULT_IGNORE = [
  'node_modules', '.git', 'dist', 'build', 'coverage', '.nyc_output',
  '.next', '.nuxt', '.svelte-kit', 'vendor', '__pycache__', '.venv',
  'venv', '.tox', 'target', 'pkg', '.cargo',
];

const BINARY_EXTENSIONS = new Set([
  '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
  '.pdf', '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.wasm',
  '.mp3', '.mp4', '.avi', '.mov', '.wav', '.flac',
  '.ttf', '.woff', '.woff2', '.eot', '.otf',
  '.pyc', '.class', '.o', '.a',
  '.db', '.sqlite', '.sqlite3',
  '.lock',
]);

function maskSecret(value: string): string {
  if (value.length <= 8) return '****';
  return value.slice(0, 4) + '****' + value.slice(-4);
}

function loadIgnorePatterns(ignoreFile: string): string[] {
  if (!fs.existsSync(ignoreFile)) return [];
  return fs.readFileSync(ignoreFile, 'utf-8')
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));
}

function matchesIgnore(filePath: string, patterns: string[]): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  for (const pattern of patterns) {
    const p = pattern.replace(/\./g, '\\.').replace(/\*\*/g, '{{GLOBSTAR}}').replace(/\*/g, '[^/]*').replace(/{{GLOBSTAR}}/g, '.*');
    const anchored = p.startsWith('/') ? '^' + p.slice(1) : '(^|/)' + p;
    try {
      if (new RegExp(anchored + '($|/)').test(normalized)) return true;
    } catch { /* skip bad patterns */ }
  }
  return false;
}

function getContextLines(lines: string[], lineIndex: number, radius = 1): string {
  const start = Math.max(0, lineIndex - radius);
  const end = Math.min(lines.length - 1, lineIndex + radius);
  return lines.slice(start, end + 1).map((l, i) => {
    const num = start + i + 1;
    const marker = (start + i) === lineIndex ? '>' : ' ';
    return `${marker} ${num}: ${l.trimEnd()}`;
  }).join('\n');
}

export async function scanFile(
  filePath: string,
  rules: SecretRule[],
  options: ScanOptions = {}
): Promise<{ findings: SecretFinding[]; error?: string }> {
  const findings: SecretFinding[] = [];

  try {
    const stat = fs.statSync(filePath);
    const maxSize = options.maxFileSize ?? 1_048_576; // 1MB
    if (stat.size > maxSize) return { findings };

    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

    for (const rule of rules) {
      // Reset regex lastIndex
      rule.pattern.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = rule.pattern.exec(content)) !== null) {
        const matchStr = match[0];
        const offset = match.index;

        // Compute line/col
        const beforeMatch = content.slice(0, offset);
        const lineIndex = beforeMatch.split('\n').length - 1;
        const lastNewline = beforeMatch.lastIndexOf('\n');
        const col = offset - lastNewline - 1;

        const lineContext = lines[lineIndex] ?? '';

        // False positive filter
        if (rule.falsePositiveFilter?.(matchStr, lineContext)) continue;

        const maskedMatch = options.showSecrets ? matchStr : maskSecret(matchStr);
        const context = getContextLines(lines, lineIndex);

        const finding: SecretFinding = {
          id: `${rule.id}-${filePath}-${lineIndex}-${col}`,
          ruleId: rule.id,
          ruleName: rule.name,
          description: rule.description,
          severity: rule.severity,
          category: rule.category,
          file: filePath,
          line: lineIndex + 1,
          column: col + 1,
          match: maskedMatch,
          context,
          recommendation: rule.recommendation,
        };

        findings.push(finding);

        // Prevent infinite loop on zero-length matches
        if (match[0].length === 0) rule.pattern.lastIndex++;
      }

      rule.pattern.lastIndex = 0;
    }
  } catch (err) {
    return { findings, error: String(err) };
  }

  return { findings };
}

function walkDir(dir: string, ignorePatterns: string[], ignoreSegments: string[]): string[] {
  const files: string[] = [];

  function walk(current: string) {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      const relPath = path.relative(dir, fullPath);

      if (ignoreSegments.includes(entry.name)) continue;
      if (matchesIgnore(relPath, ignorePatterns)) continue;

      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (BINARY_EXTENSIONS.has(ext)) continue;
        files.push(fullPath);
      }
    }
  }

  walk(dir);
  return files;
}

export async function scan(targetPath: string, options: ScanOptions = {}): Promise<ScanResult> {
  const start = Date.now();
  const allFindings: SecretFinding[] = [];
  const errors: Array<{ file: string; error: string }> = [];

  // Build ignore list
  const ignoreSegments = [...DEFAULT_IGNORE, ...(options.ignore ?? [])];
  const ignorePatterns: string[] = [];
  const ignoreFile = options.ignoreFile ?? path.join(process.cwd(), '.secretvetignore');
  ignorePatterns.push(...loadIgnorePatterns(ignoreFile));

  // Filter rules by severity
  const minSev = options.minSeverity ? SEVERITY_ORDER[options.minSeverity] : 0;
  const rules = ALL_RULES.filter(r => SEVERITY_ORDER[r.severity] >= minSev);

  // Collect files
  const stat = fs.statSync(targetPath);
  const files: string[] = stat.isDirectory()
    ? walkDir(targetPath, ignorePatterns, ignoreSegments)
    : [targetPath];

  let filesScanned = 0;
  let filesSkipped = 0;

  for (const file of files) {
    const result = await scanFile(file, rules, options);
    if (result.error) {
      errors.push({ file, error: result.error });
      filesSkipped++;
    } else {
      allFindings.push(...result.findings);
      filesScanned++;
    }
  }

  const summary = {
    critical: allFindings.filter(f => f.severity === 'critical').length,
    high: allFindings.filter(f => f.severity === 'high').length,
    medium: allFindings.filter(f => f.severity === 'medium').length,
    low: allFindings.filter(f => f.severity === 'low').length,
    info: allFindings.filter(f => f.severity === 'info').length,
    total: allFindings.length,
  };

  return {
    target: targetPath,
    timestamp: new Date().toISOString(),
    duration: Date.now() - start,
    filesScanned,
    filesSkipped,
    findings: allFindings,
    summary,
    version: VERSION,
    errors,
  };
}
