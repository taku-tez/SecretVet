import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { shannonEntropy } from '../src/rules/generic.js';

describe('Shannon Entropy', () => {
  test('returns 0 for empty string', () => {
    assert.strictEqual(shannonEntropy(''), 0);
  });

  test('returns 0 for single repeated character', () => {
    assert.strictEqual(shannonEntropy('aaaaaaa'), 0);
  });

  test('low entropy for simple strings', () => {
    const e = shannonEntropy('abcabc');
    assert.ok(e < 3, `Expected low entropy, got ${e}`);
  });

  test('high entropy for random-looking strings', () => {
    // Typical API key pattern - high entropy
    const e = shannonEntropy('aB3$kP9mQrXv2nZwYt5u');
    assert.ok(e > 3.5, `Expected high entropy for API-like string, got ${e}`);
  });

  test('high entropy for base64 secrets', () => {
    const e = shannonEntropy('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
    assert.ok(e > 4.0, `Expected high entropy for AWS secret-like string, got ${e}`);
  });

  test('low entropy for placeholder strings', () => {
    const e = shannonEntropy('YOUR_API_KEY_HERE');
    assert.ok(e < 4.0, `Expected lower entropy for placeholder, got ${e}`);
  });
});
