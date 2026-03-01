import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { scan, scanFile } from '../src/scanner.js';
import { ALL_RULES } from '../src/rules/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = path.join(__dirname, 'fixtures');
const TRUE_POS_DIR = path.join(FIXTURES_DIR, 'true-positives');
const FALSE_POS_DIR = path.join(FIXTURES_DIR, 'false-positives');

describe('Scanner - True Positives', () => {
  test('should detect secrets in true-positive fixtures', async () => {
    const result = await scan(TRUE_POS_DIR, { showSecrets: false });
    assert.ok(result.findings.length > 0, `Expected findings, got 0. Files: ${result.filesScanned}`);
  });

  test('should detect AWS access key', async () => {
    const awsFile = path.join(TRUE_POS_DIR, 'aws.env');
    const { findings } = await scanFile(awsFile, ALL_RULES, {});
    const awsFindings = findings.filter(f => f.ruleId === 'secret-aws-access-key');
    assert.ok(awsFindings.length > 0, 'Should detect AWS Access Key ID');
  });

  test('should detect OpenAI key', async () => {
    const keysFile = path.join(TRUE_POS_DIR, 'keys.ts');
    const { findings } = await scanFile(keysFile, ALL_RULES, {});
    const openaiFindings = findings.filter(f => f.ruleId === 'secret-openai-key');
    assert.ok(openaiFindings.length > 0, 'Should detect OpenAI key');
  });

  test('should detect GitHub token', async () => {
    const keysFile = path.join(TRUE_POS_DIR, 'keys.ts');
    const { findings } = await scanFile(keysFile, ALL_RULES, {});
    const ghFindings = findings.filter(f => f.ruleId === 'secret-github-pat');
    assert.ok(ghFindings.length > 0, 'Should detect GitHub PAT');
  });

  test('should detect Stripe key via rule pattern', () => {
    const rule = ALL_RULES.find(r => r.id === 'secret-stripe-secret-key');
    assert.ok(rule, 'Stripe rule should exist');
    const testKey = ['sk', 'live', 'abcdefghijklmnopqrstuvwx'].join('_');
    rule!.pattern.lastIndex = 0;
    const match = rule!.pattern.exec(testKey);
    rule!.pattern.lastIndex = 0;
    assert.ok(match, 'Should detect Stripe secret key');
  });

  test('should detect SSH private key', async () => {
    const keysFile = path.join(TRUE_POS_DIR, 'keys.ts');
    const { findings } = await scanFile(keysFile, ALL_RULES, {});
    const sshFindings = findings.filter(f => f.ruleId === 'secret-ssh-openssh-key');
    assert.ok(sshFindings.length > 0, 'Should detect SSH private key');
  });

  test('should mask secrets by default', async () => {
    const awsFile = path.join(TRUE_POS_DIR, 'aws.env');
    const { findings } = await scanFile(awsFile, ALL_RULES, { showSecrets: false });
    for (const f of findings) {
      assert.ok(f.match.includes('****'), `Match should be masked: ${f.match}`);
    }
  });

  test('should show secrets when showSecrets=true', async () => {
    const awsFile = path.join(TRUE_POS_DIR, 'aws.env');
    const { findings } = await scanFile(awsFile, ALL_RULES, { showSecrets: true });
    const awsFinding = findings.find(f => f.ruleId === 'secret-aws-access-key');
    assert.ok(awsFinding, 'Should have AWS finding');
    assert.ok(awsFinding.match.startsWith('AKIA'), 'Should show unmasked AKIA secret');
    assert.ok(!awsFinding.match.includes('****'), 'Should not mask when showSecrets=true');
  });
});

describe('Scanner - False Positives', () => {
  test('should not flag placeholder values', async () => {
    const safeFile = path.join(FALSE_POS_DIR, 'safe.ts');
    const { findings } = await scanFile(safeFile, ALL_RULES, {});

    // Filter out generic entropy matches which are harder to exclude
    const criticalHighFindings = findings.filter(
      f => f.severity === 'critical' || f.severity === 'high'
    );
    assert.strictEqual(
      criticalHighFindings.length,
      0,
      `Should not have critical/high findings in safe file, got: ${criticalHighFindings.map(f => `${f.ruleId} "${f.match}"`).join(', ')}`
    );
  });
});

describe('Scanner - Options', () => {
  test('should respect minSeverity filter', async () => {
    const result = await scan(TRUE_POS_DIR, { minSeverity: 'critical' });
    for (const f of result.findings) {
      assert.ok(
        f.severity === 'critical',
        `Expected only critical findings, got: ${f.severity} for ${f.ruleId}`
      );
    }
  });

  test('should return correct summary counts', async () => {
    const result = await scan(TRUE_POS_DIR, {});
    const { summary } = result;
    assert.strictEqual(
      summary.total,
      result.findings.length,
      'Summary total should match findings length'
    );
    assert.strictEqual(
      summary.critical + summary.high + summary.medium + summary.low + summary.info,
      summary.total,
      'Summary counts should add up to total'
    );
  });

  test('should include file metadata in results', async () => {
    const result = await scan(TRUE_POS_DIR, {});
    assert.ok(result.filesScanned > 0, 'Should scan at least one file');
    assert.ok(result.timestamp, 'Should have timestamp');
    assert.ok(result.duration >= 0, 'Should have duration');
    assert.ok(result.version, 'Should have version');
  });

  test('should exclude generic/entropy rules when entropy=false', async () => {
    const withEntropy = await scan(TRUE_POS_DIR, { entropy: true });
    const withoutEntropy = await scan(TRUE_POS_DIR, { entropy: false });

    const genericWithEntropy = withEntropy.findings.filter(f => f.category === 'generic');
    const genericWithoutEntropy = withoutEntropy.findings.filter(f => f.category === 'generic');

    assert.strictEqual(genericWithoutEntropy.length, 0, 'Should have no generic findings when entropy=false');
    // With entropy enabled, generic rules may or may not fire depending on content
    assert.ok(
      genericWithEntropy.length >= genericWithoutEntropy.length,
      'Should have at least as many generic findings with entropy=true as with entropy=false'
    );
  });
});
