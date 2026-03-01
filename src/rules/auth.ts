import type { SecretRule } from '../types.js';

export const rules: SecretRule[] = [
  {
    id: 'secret-private-key-pem',
    name: 'PEM Private Key',
    description: 'RSA/EC/DSA private key in PEM format detected',
    severity: 'critical',
    category: 'auth',
    pattern: /-----BEGIN (?:RSA |EC |DSA |ECDSA )?PRIVATE KEY-----[\s\S]{64,}?-----END (?:RSA |EC |DSA |ECDSA )?PRIVATE KEY-----/g,
    recommendation: 'Never commit private keys. Use a secrets manager or environment variables.',
    references: ['https://cwe.mitre.org/data/definitions/321.html'],
  },
  {
    id: 'secret-ssh-openssh-key',
    name: 'SSH OpenSSH Private Key',
    description: 'OpenSSH private key detected',
    severity: 'critical',
    category: 'auth',
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]{64,}?-----END OPENSSH PRIVATE KEY-----/g,
    recommendation: 'Remove this private key immediately. Use SSH key management tools.',
  },
  {
    id: 'secret-pgp-private-key',
    name: 'PGP Private Key',
    description: 'PGP private key block detected',
    severity: 'critical',
    category: 'auth',
    pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]{64,}?-----END PGP PRIVATE KEY BLOCK-----/g,
    recommendation: 'Remove this PGP private key. Use GPG agent or secrets manager.',
  },
  {
    id: 'secret-jwt-token',
    name: 'JWT Token',
    description: 'JSON Web Token detected (may contain sensitive claims)',
    severity: 'medium',
    category: 'auth',
    pattern: /\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b/g,
    recommendation: 'Do not commit JWT tokens. They may contain sensitive user data and could grant unauthorized access.',
    falsePositiveFilter: (match, context) => {
      // Skip if it looks like a test/example
      return /test|example|sample|dummy|mock/i.test(context);
    },
  },
  {
    id: 'secret-ethereum-private-key',
    name: 'Ethereum Private Key',
    description: 'Ethereum/EVM private key detected (64 hex chars with context)',
    severity: 'critical',
    category: 'auth',
    pattern: /(?:private[_\-.]?key|eth[_\-.]?key|wallet[_\-.]?key)\s*[=:'"]+\s*['"]?(?:0x)?([a-fA-F0-9]{64})['"]?/gi,
    recommendation: 'Never commit crypto private keys. Use a hardware wallet or encrypted keystore.',
  },
  {
    id: 'secret-pkcs12-key',
    name: 'PKCS12 / PFX Certificate',
    description: 'PKCS12 certificate password in context detected',
    severity: 'high',
    category: 'auth',
    pattern: /(?:pkcs12|pfx|p12)[_\-.]?(?:password|passphrase|pass)\s*[=:'"]+\s*['"]?([A-Za-z0-9!@#$%^&*]{8,})['"]?/gi,
    recommendation: 'Use environment variables for certificate passwords.',
    falsePositiveFilter: (match, context) => /test|example|sample|dummy/i.test(context),
  },
  {
    id: 'secret-basic-auth-url',
    name: 'HTTP Basic Auth in URL',
    description: 'HTTP Basic Auth credentials embedded in URL detected',
    severity: 'high',
    category: 'auth',
    pattern: /https?:\/\/[a-zA-Z0-9_\-]+:[^@\s'"]{6,}@[a-zA-Z0-9.\-]+/g,
    recommendation: 'Never embed credentials in URLs. Use environment variables or credential managers.',
    falsePositiveFilter: (match) =>
      /localhost|127\.0\.0\.1|example\.com|test\.com/i.test(match)
      || /\$\{[^}]+\}/.test(match)   // template literal ${token}@host
      || /\$\([^)]+\)/.test(match),  // shell var $(token)@host
  },
];
