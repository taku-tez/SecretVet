import type { SecretRule } from '../types.js';

const PLACEHOLDER_RE = /your[_-]?(api[_-]?)?key|example|dummy|placeholder|xxx+|test[_-]?key|fake|sample|changeme|\*{4,}/i;

function isPlaceholder(match: string): boolean {
  return PLACEHOLDER_RE.test(match);
}

export const rules: SecretRule[] = [
  {
    id: 'secret-stripe-secret-key',
    name: 'Stripe Secret Key',
    description: 'Stripe live secret key detected',
    severity: 'critical',
    category: 'payment',
    pattern: /\bsk_live_[0-9a-zA-Z]{24,}\b/g,
    recommendation: 'Rotate this Stripe key at dashboard.stripe.com/apikeys. Never commit live keys.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-stripe-test-key',
    name: 'Stripe Test Key',
    description: 'Stripe test secret key detected',
    severity: 'medium',
    category: 'payment',
    pattern: /\bsk_test_[0-9a-zA-Z]{24,}\b/g,
    recommendation: 'Test keys should also be kept out of source code. Use environment variables.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-stripe-restricted-key',
    name: 'Stripe Restricted Key',
    description: 'Stripe restricted API key detected',
    severity: 'critical',
    category: 'payment',
    pattern: /\brk_live_[0-9a-zA-Z]{24,}\b/g,
    recommendation: 'Rotate this Stripe restricted key immediately.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-stripe-webhook-secret',
    name: 'Stripe Webhook Secret',
    description: 'Stripe webhook signing secret detected',
    severity: 'high',
    category: 'payment',
    pattern: /\bwhsec_[0-9a-zA-Z]{32,}\b/g,
    recommendation: 'Rotate this webhook signing secret in Stripe dashboard.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-square-access-token',
    name: 'Square Access Token',
    description: 'Square payment access token detected',
    severity: 'critical',
    category: 'payment',
    pattern: /\bsq0atp-[0-9A-Za-z\-_]{22}\b/g,
    recommendation: 'Rotate this Square token at developer.squareup.com.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-square-app-secret',
    name: 'Square Application Secret',
    description: 'Square application secret detected',
    severity: 'critical',
    category: 'payment',
    pattern: /\bsq0csp-[0-9A-Za-z\-_]{43}\b/g,
    recommendation: 'Rotate this Square application secret.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-paypal-braintree-key',
    name: 'PayPal/Braintree Key',
    description: 'Braintree payment gateway key detected',
    severity: 'critical',
    category: 'payment',
    pattern: /(?:braintree|paypal)[_\-.]?(?:private[_\-.]?)?(?:key|secret|token)\s*[=:'"]+\s*['"]?([A-Za-z0-9]{32})['"]?/gi,
    recommendation: 'Rotate this Braintree key at braintreepayments.com.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
  {
    id: 'secret-adyen-api-key',
    name: 'Adyen API Key',
    description: 'Adyen payment API key detected',
    severity: 'critical',
    category: 'payment',
    pattern: /\bAQE[a-zA-Z0-9+/=]{60,}\b/g,
    recommendation: 'Rotate this Adyen API key in the Customer Area.',
    falsePositiveFilter: (match) => isPlaceholder(match),
  },
];
