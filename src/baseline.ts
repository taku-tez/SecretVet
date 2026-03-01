import * as fs from 'fs';
import * as crypto from 'crypto';
import type { SecretFinding, ScanResult } from './types.js';

export interface BaselineEntry {
  id: string;
  ruleId: string;
  file: string;
  line: number;
  fingerprint: string;
  addedAt: string;
  note?: string;
}

export interface Baseline {
  version: string;
  createdAt: string;
  updatedAt: string;
  entries: BaselineEntry[];
}

const BASELINE_VERSION = '1';

function fingerprintFinding(finding: SecretFinding): string {
  const raw = `${finding.ruleId}:${finding.file}:${finding.line}:${finding.match}`;
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
}

export function loadBaseline(baselinePath: string): Baseline {
  if (!fs.existsSync(baselinePath)) {
    return {
      version: BASELINE_VERSION,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      entries: [],
    };
  }

  try {
    const raw = fs.readFileSync(baselinePath, 'utf-8');
    return JSON.parse(raw) as Baseline;
  } catch {
    throw new Error(`Failed to parse baseline file: ${baselinePath}`);
  }
}

export function saveBaseline(baseline: Baseline, baselinePath: string): void {
  baseline.updatedAt = new Date().toISOString();
  fs.writeFileSync(baselinePath, JSON.stringify(baseline, null, 2), 'utf-8');
}

export function createBaseline(result: ScanResult, note?: string): Baseline {
  const now = new Date().toISOString();
  const entries: BaselineEntry[] = result.findings.map(f => ({
    id: f.id,
    ruleId: f.ruleId,
    file: f.file,
    line: f.line,
    fingerprint: fingerprintFinding(f),
    addedAt: now,
    note,
  }));

  return {
    version: BASELINE_VERSION,
    createdAt: now,
    updatedAt: now,
    entries,
  };
}

export function filterBaselineFindings(
  findings: SecretFinding[],
  baseline: Baseline
): { newFindings: SecretFinding[]; baselineFindings: SecretFinding[] } {
  const baselineFingerprints = new Set(baseline.entries.map(e => e.fingerprint));

  const newFindings: SecretFinding[] = [];
  const baselineFindings: SecretFinding[] = [];

  for (const f of findings) {
    const fp = fingerprintFinding(f);
    if (baselineFingerprints.has(fp)) {
      baselineFindings.push(f);
    } else {
      newFindings.push(f);
    }
  }

  return { newFindings, baselineFindings };
}

export function updateBaseline(
  existing: Baseline,
  newFindings: SecretFinding[],
  note?: string
): Baseline {
  const now = new Date().toISOString();
  const existingFingerprints = new Set(existing.entries.map(e => e.fingerprint));

  const newEntries: BaselineEntry[] = newFindings
    .filter(f => !existingFingerprints.has(fingerprintFinding(f)))
    .map(f => ({
      id: f.id,
      ruleId: f.ruleId,
      file: f.file,
      line: f.line,
      fingerprint: fingerprintFinding(f),
      addedAt: now,
      note,
    }));

  return {
    ...existing,
    updatedAt: now,
    entries: [...existing.entries, ...newEntries],
  };
}
