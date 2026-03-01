# 🔐 SecretVet

**Secret and credential scanner for source code, git history, and CI/CD configs.**

Part of the [xxVet security tool series](https://github.com/taku-tez).

## Installation

```bash
npm install -g @secretvet/cli
```

## Usage

```bash
# Scan current directory
secretvet scan .

# Scan with JSON output
secretvet scan ./src --format json

# Scan for GitHub Advanced Security (SARIF)
secretvet scan . --format sarif > results.sarif

# Only show critical and high findings
secretvet scan . --min-severity high

# List available rules
secretvet rules list

# List rules by category
secretvet rules list --category cloud
```

## Features

- **100+ secret patterns** covering all major providers
- **8 categories**: cloud, AI, payment, communication, VCS, database, auth, CI/CD
- **Entropy analysis** for detecting unknown/custom secret formats
- **False positive filtering** — placeholders, test values, env var references auto-excluded
- **Secret masking** — detected values shown as `sk-****...abcd` by default
- **SARIF output** — GitHub Advanced Security compatible
- **Zero dependencies** — pure Node.js

## Rule Categories

| Category | Examples |
|----------|---------|
| `cloud` | AWS, GCP, Azure, Alibaba Cloud, DigitalOcean, Cloudflare |
| `ai` | OpenAI, Anthropic, HuggingFace, Replicate, Groq, Mistral |
| `payment` | Stripe, Square, PayPal/Braintree, Adyen |
| `communication` | Slack, Discord, Twilio, SendGrid, Mailgun, Telegram |
| `vcs` | GitHub (all token types), GitLab, Bitbucket |
| `database` | MongoDB Atlas, PostgreSQL, MySQL, Redis, Supabase |
| `auth` | RSA/EC private keys, SSH keys, PGP keys, JWT tokens, Ethereum keys |
| `cicd` | npm, PyPI, Docker Hub, CircleCI, Travis CI, Terraform, Vault |

## Exit Codes

- `0` — No critical or high findings
- `1` — Critical or high severity secrets found (or scan error)

## GitHub Actions

```yaml
- name: SecretVet Scan
  run: |
    npm install -g @secretvet/cli
    secretvet scan . --format sarif > secretvet.sarif
  
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: secretvet.sarif
```

## Ignoring Files

Create `.secretvetignore` in your project root (same format as `.gitignore`):

```
test/fixtures/
docs/
*.example.env
```

## License

MIT
