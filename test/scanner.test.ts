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
});

describe('Scanner - False Positive Reduction (Issue #10)', () => {
  test('should downgrade severity for markdown code block findings to info', async () => {
    const mdFile = path.join(FALSE_POS_DIR, 'docs-example.md');
    const { findings } = await scanFile(mdFile, ALL_RULES, { showSecrets: true });
    // Findings inside fenced code blocks should be severity=info
    const fencedFindings = findings.filter(f => f.line >= 5 && f.line <= 7);
    for (const f of fencedFindings) {
      assert.strictEqual(f.severity, 'info', `Finding in markdown code block should be info, got ${f.severity} for ${f.ruleId} at line ${f.line}`);
    }
  });

  test('should downgrade severity for indented code block in markdown', async () => {
    const mdFile = path.join(FALSE_POS_DIR, 'docs-example.md');
    const { findings } = await scanFile(mdFile, ALL_RULES, { showSecrets: true });
    // The 4-space indented line is line 11
    const indentedFindings = findings.filter(f => f.line === 11);
    for (const f of indentedFindings) {
      assert.strictEqual(f.severity, 'info', `Finding in indented code block should be info, got ${f.severity} for ${f.ruleId}`);
    }
  });

  test('should downgrade severity for test directory files', async () => {
    const testDir = path.join(FALSE_POS_DIR);
    const result = await scan(testDir, { showSecrets: true });
    // Findings from test/ subdirectory should have downgraded severity
    const testFindings = result.findings.filter(f => f.file.includes('/test/'));
    for (const f of testFindings) {
      assert.ok(
        f.severity !== 'critical',
        `Test file finding should not be critical, got ${f.severity} for ${f.ruleId} in ${f.file}`
      );
    }
  });

  test('should skip git commit hashes with git context keywords', async () => {
    const gitFile = path.join(FALSE_POS_DIR, 'git-hashes.sh');
    const { findings } = await scanFile(gitFile, ALL_RULES, { showSecrets: true });
    // Should not have findings matching the 40-char hex hashes
    const hashFindings = findings.filter(f =>
      f.match.includes('abcdef1234567890abcdef1234567890abcdef12')
    );
    assert.strictEqual(
      hashFindings.length,
      0,
      `Should not flag git commit hashes, got ${hashFindings.length} findings: ${hashFindings.map(f => f.ruleId).join(', ')}`
    );
  });
});
