import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';
import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';
import { fileURLToPath } from 'url';
import type { SecretFinding, ScanOptions, Severity } from './types.js';

// Worker message types
interface WorkerInput {
  files: string[];
  rulesJson: SerializedRule[];
  options: ScanOptions;
}

interface SerializedRule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: string;
  patternSource: string;
  patternFlags: string;
  recommendation: string;
  // falsePositiveFilter as string (function body) — not serializable as function
  fpRegexes?: string[];
}

interface WorkerOutput {
  findings: SecretFinding[];
  errors: Array<{ file: string; error: string }>;
  filesScanned: number;
  filesSkipped: number;
}

// ---- Worker thread code ----
// When this module runs as a worker, process the files
if (!isMainThread && parentPort) {
  const { files, rulesJson, options } = workerData as WorkerInput;

  // Reconstruct rules from serialized form
  const rules = rulesJson.map(r => ({
    ...r,
    pattern: new RegExp(r.patternSource, r.patternFlags),
    falsePositiveFilter: r.fpRegexes?.length
      ? (match: string) => r.fpRegexes!.some(re => new RegExp(re, 'i').test(match))
      : undefined,
  }));

  const BINARY_EXTENSIONS = new Set([
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.pdf',
    '.zip', '.tar', '.gz', '.bz2', '.7z', '.exe', '.dll',
    '.so', '.dylib', '.bin', '.wasm', '.pyc', '.class',
    '.db', '.sqlite', '.lock',
  ]);

  function maskSecret(value: string): string {
    if (value.length <= 8) return '****';
    return value.slice(0, 4) + '****' + value.slice(-4);
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

  const output: WorkerOutput = {
    findings: [],
    errors: [],
    filesScanned: 0,
    filesSkipped: 0,
  };

  const maxSize = options.maxFileSize ?? 1_048_576;

  for (const filePath of files) {
    const ext = path.extname(filePath).toLowerCase();
    if (BINARY_EXTENSIONS.has(ext)) { output.filesSkipped++; continue; }

    try {
      const stat = fs.statSync(filePath);
      if (stat.size > maxSize) { output.filesSkipped++; continue; }

      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      for (const rule of rules) {
        rule.pattern.lastIndex = 0;
        let match: RegExpExecArray | null;

        while ((match = rule.pattern.exec(content)) !== null) {
          const matchStr = match[0];
          const beforeMatch = content.slice(0, match.index);
          const lineIndex = beforeMatch.split('\n').length - 1;
          const lastNewline = beforeMatch.lastIndexOf('\n');
          const col = match.index - lastNewline - 1;
          const lineContext = lines[lineIndex] ?? '';

          if (rule.falsePositiveFilter?.(matchStr)) {
            if (match[0].length === 0) rule.pattern.lastIndex++;
            continue;
          }

          const maskedMatch = options.showSecrets ? matchStr : maskSecret(matchStr);
          output.findings.push({
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
            context: getContextLines(lines, lineIndex),
            recommendation: rule.recommendation,
          });

          if (match[0].length === 0) rule.pattern.lastIndex++;
        }
        rule.pattern.lastIndex = 0;
      }

      output.filesScanned++;
    } catch (err) {
      output.errors.push({ file: filePath, error: String(err) });
      output.filesSkipped++;
    }
  }

  parentPort.postMessage(output);
}

// ---- Main thread code ----

function serializeRules(rules: any[]): SerializedRule[] {
  return rules.map(r => ({
    id: r.id,
    name: r.name,
    description: r.description,
    severity: r.severity,
    category: r.category,
    patternSource: r.pattern.source,
    patternFlags: r.pattern.flags,
    recommendation: r.recommendation,
    fpRegexes: undefined, // falsePositiveFilter is too complex to serialize generically
  }));
}

function chunkArray<T>(arr: T[], n: number): T[][] {
  const size = Math.ceil(arr.length / n);
  return Array.from({ length: n }, (_, i) => arr.slice(i * size, (i + 1) * size)).filter(c => c.length > 0);
}

function runWorker(workerPath: string, input: WorkerInput): Promise<WorkerOutput> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(workerPath, { workerData: input });
    worker.once('message', resolve);
    worker.once('error', reject);
    worker.once('exit', code => {
      if (code !== 0) reject(new Error(`Worker exited with code ${code}`));
    });
  });
}

export async function scanParallel(
  files: string[],
  rules: any[],
  options: ScanOptions,
  numWorkers?: number,
): Promise<{ findings: SecretFinding[]; errors: Array<{ file: string; error: string }>; filesScanned: number; filesSkipped: number }> {
  const workers = numWorkers ?? Math.max(1, Math.min(os.cpus().length - 1, 8));

  if (files.length < 50 || workers === 1) {
    // Fall back to sequential for small file sets — overhead not worth it
    const { scanFile } = await import('./scanner.js');
    const findings: SecretFinding[] = [];
    const errors: Array<{ file: string; error: string }> = [];
    let filesScanned = 0;
    let filesSkipped = 0;

    for (const file of files) {
      const result = await scanFile(file, rules, options);
      if (result.error) { errors.push({ file, error: result.error }); filesSkipped++; }
      else { findings.push(...result.findings); filesScanned++; }
    }
    return { findings, errors, filesScanned, filesSkipped };
  }

  const chunks = chunkArray(files, workers);
  const serializedRules = serializeRules(rules);

  // Use the current file as the worker script
  const workerPath = fileURLToPath(import.meta.url);

  const results = await Promise.all(
    chunks.map(chunk =>
      runWorker(workerPath, { files: chunk, rulesJson: serializedRules, options })
    )
  );

  return results.reduce(
    (acc, r) => ({
      findings: [...acc.findings, ...r.findings],
      errors: [...acc.errors, ...r.errors],
      filesScanned: acc.filesScanned + r.filesScanned,
      filesSkipped: acc.filesSkipped + r.filesSkipped,
    }),
    { findings: [], errors: [], filesScanned: 0, filesSkipped: 0 }
  );
}
