import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createBaseline, loadBaseline, saveBaseline,
  filterBaselineFindings, updateBaseline,
} from '../src/baseline.js';
import type { SecretFinding, ScanResult } from '../src/types.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function makeFinding(overrides: Partial<SecretFinding> = {}): SecretFinding {
  return {
    id: 'secret-aws-access-key-test.ts-1-1',
    ruleId: 'secret-aws-access-key',
    ruleName: 'AWS Access Key ID',
    description: 'AWS Access Key ID detected',
    severity: 'critical',
    category: 'cloud',
    file: 'test.ts',
    line: 1,
    column: 1,
    match: 'AKIA****LKEY',
    context: '> 1: const key = "AKIA[REDACTED]"',
    recommendation: 'Use environment variables',
    ...overrides,
  };
}

function makeScanResult(findings: SecretFinding[]): ScanResult {
  return {
    target: '.',
    timestamp: new Date().toISOString(),
    duration: 10,
    filesScanned: 1,
    filesSkipped: 0,
    findings,
    summary: {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
      info: findings.filter(f => f.severity === 'info').length,
      total: findings.length,
    },
    version: '0.1.0',
    errors: [],
  };
}

describe('Baseline', () => {
  test('createBaseline generates correct structure', () => {
    const findings = [makeFinding()];
    const result = makeScanResult(findings);
    const baseline = createBaseline(result, 'test baseline');

    assert.strictEqual(baseline.version, '1');
    assert.strictEqual(baseline.entries.length, 1);
    assert.ok(baseline.entries[0].fingerprint, 'Should have fingerprint');
    assert.ok(baseline.entries[0].addedAt, 'Should have addedAt');
    assert.strictEqual(baseline.entries[0].note, 'test baseline');
  });

  test('filterBaselineFindings separates new from known', () => {
    const finding1 = makeFinding({ id: 'f1', line: 1 });
    const finding2 = makeFinding({ id: 'f2', line: 2, match: 'AKIA****DIFF' });

    const result = makeScanResult([finding1]);
    const baseline = createBaseline(result);

    const allFindings = [finding1, finding2];
    const { newFindings, baselineFindings } = filterBaselineFindings(allFindings, baseline);

    assert.strictEqual(newFindings.length, 1, 'Should have 1 new finding');
    assert.strictEqual(baselineFindings.length, 1, 'Should have 1 baseline finding');
    assert.strictEqual(newFindings[0].id, 'f2');
  });

  test('updateBaseline adds only new findings', () => {
    const finding1 = makeFinding({ id: 'f1', line: 1 });
    const finding2 = makeFinding({ id: 'f2', line: 2, match: 'AKIA****DIFF' });

    const result = makeScanResult([finding1]);
    const baseline = createBaseline(result);

    const updated = updateBaseline(baseline, [finding1, finding2]);
    assert.strictEqual(updated.entries.length, 2, 'Should have 2 entries after update');
  });

  test('saveBaseline and loadBaseline roundtrip', () => {
    const tmpDir = os.tmpdir();
    const tmpFile = path.join(tmpDir, `secretvet-test-${Date.now()}.json`);

    try {
      const findings = [makeFinding()];
      const result = makeScanResult(findings);
      const baseline = createBaseline(result);

      saveBaseline(baseline, tmpFile);
      assert.ok(fs.existsSync(tmpFile), 'Baseline file should exist');

      const loaded = loadBaseline(tmpFile);
      assert.strictEqual(loaded.entries.length, 1);
      assert.strictEqual(loaded.entries[0].ruleId, 'secret-aws-access-key');
    } finally {
      if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
    }
  });

  test('loadBaseline returns empty baseline for missing file', () => {
    const baseline = loadBaseline('/nonexistent/path/baseline.json');
    assert.strictEqual(baseline.entries.length, 0);
    assert.strictEqual(baseline.version, '1');
  });

  test('same finding in same location gets same fingerprint', () => {
    const finding = makeFinding();
    const result = makeScanResult([finding]);
    const baseline1 = createBaseline(result);
    const baseline2 = createBaseline(result);

    assert.strictEqual(
      baseline1.entries[0].fingerprint,
      baseline2.entries[0].fingerprint,
      'Same finding should produce same fingerprint'
    );
  });

  test('different findings get different fingerprints', () => {
    const finding1 = makeFinding({ line: 1, match: 'AKIA****AAA1' });
    const finding2 = makeFinding({ line: 2, match: 'AKIA****BBB2' });

    const result = makeScanResult([finding1, finding2]);
    const baseline = createBaseline(result);

    assert.notStrictEqual(
      baseline.entries[0].fingerprint,
      baseline.entries[1].fingerprint,
      'Different findings should have different fingerprints'
    );
  });
});
