import type { SecretRule } from '../types.js';

const SECRET_KEYWORDS = /(?:^|[\s,;{(\[])(?:api[_\-.]?key|api[_\-.]?secret|access[_\-.]?token|auth[_\-.]?token|secret[_\-.]?key|private[_\-.]?key|client[_\-.]?secret|encryption[_\-.]?key|signing[_\-.]?key|bearer[_\-.]?token|credential|passwd|password)\s*[=:'"]+\s*['"]?/i;

const PLACEHOLDER_RE = /your[_-]?(api[_-]?)?key|example|dummy|placeholder|xxx+|test[_-]?key|fake|sample|changeme|\*{4,}|<[^>]+>|\$\{[^}]+\}|%[A-Z_]+%/i;

export function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] ?? 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export const rules: SecretRule[] = [
  {
    id: 'secret-high-entropy-string',
    name: 'High Entropy String',
    description: 'High-entropy string in secret-related variable detected',
    severity: 'medium',
    category: 'generic',
    // Match variable assignment context + a long alphanum+symbols string
    pattern: /(?:api[_\-.]?key|api[_\-.]?secret|access[_\-.]?token|auth[_\-.]?token|secret[_\-.]?key|private[_\-.]?key|client[_\-.]?secret|encryption[_\-.]?key|signing[_\-.]?key|bearer[_\-.]?token|credential|passwd|password)\s*[=:'"]+\s*['"]?([A-Za-z0-9+/=_\-!@#$%^&*]{24,})['"]?/gi,
    recommendation: 'Verify this is not a real secret. Use environment variables for credentials.',
    falsePositiveFilter: (match, context) => {
      if (PLACEHOLDER_RE.test(match)) return true;
      // Check entropy of the captured value
      const valueMatch = match.match(/['"]?([A-Za-z0-9+/=_\-!@#$%^&*]{24,})['"]?\s*$/);
      if (!valueMatch) return true;
      const value = valueMatch[1];
      return shannonEntropy(value) < 3.5;
    },
  },
  {
    id: 'secret-high-entropy-hex',
    name: 'High Entropy Hex String',
    description: 'High-entropy hex string in secret variable context detected',
    severity: 'medium',
    category: 'generic',
    pattern: /(?:secret|token|key|hash|signature|digest)\s*[=:'"]+\s*['"]?([a-f0-9]{32,})['"]?/gi,
    recommendation: 'Verify this hex string is not a real secret or key.',
    falsePositiveFilter: (match) => {
      if (PLACEHOLDER_RE.test(match)) return true;
      const hexMatch = match.match(/['"=:\s]+([a-f0-9]{32,})/i);
      if (!hexMatch) return true;
      return shannonEntropy(hexMatch[1]) < 3.0;
    },
  },
  {
    id: 'secret-high-entropy-base64',
    name: 'High Entropy Base64 String',
    description: 'High-entropy Base64 string in secret variable context detected',
    severity: 'medium',
    category: 'generic',
    pattern: /(?:secret|token|key|credential|certificate)\s*[=:'"]+\s*['"]?([A-Za-z0-9+/]{40,}={0,2})['"]?/gi,
    recommendation: 'Verify this Base64 string is not an encoded secret or key.',
    falsePositiveFilter: (match) => {
      if (PLACEHOLDER_RE.test(match)) return true;
      const b64Match = match.match(/['"=:\s]+([A-Za-z0-9+/]{40,}={0,2})/);
      if (!b64Match) return true;
      return shannonEntropy(b64Match[1]) < 4.0;
    },
  },
];
