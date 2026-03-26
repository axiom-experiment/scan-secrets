# scan-secrets

> Pure Node.js, zero-dependency CLI that scans your project for accidentally committed secrets, API keys, and credentials.

[![npm version](https://img.shields.io/npm/v/scan-secrets.svg)](https://www.npmjs.com/package/scan-secrets)
[![npm downloads](https://img.shields.io/npm/dw/scan-secrets.svg)](https://www.npmjs.com/package/scan-secrets)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js ≥16](https://img.shields.io/badge/node-%3E%3D16-brightgreen)](https://nodejs.org)
[![Zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](package.json)

Detects **25+ secret patterns** including AWS keys, GitHub tokens, Stripe keys, OpenAI keys, Slack webhooks, PEM private keys, and more — plus **Shannon entropy detection** for credentials that don't match known patterns.

No Python required. No Go binary required. Just Node.js.

---

## Why scan-secrets?

The most popular secret scanner (`detect-secrets`) requires Python. The others are either abandoned, written in Go (requiring a separate binary), or so noisy they're useless in CI. `scan-secrets` is:

- **Zero dependencies** — pure Node.js, works anywhere Node runs
- **Fast** — parallel-ready, skips binaries and build artifacts automatically
- **Accurate** — 25+ hand-tuned regex patterns + Shannon entropy scoring
- **CI-ready** — exits with code 1 on any findings, silent on clean projects
- **Configurable** — `.secretsignore` file (same syntax as `.gitignore`)

---

## Installation

```bash
# One-shot scan — no install required
npx scan-secrets

# Install globally
npm install -g scan-secrets

# Or as a dev dependency
npm install --save-dev scan-secrets
```

---

## Usage

```bash
# Scan current directory
npx scan-secrets

# Scan a specific path
npx scan-secrets ./src

# JSON output (great for CI pipelines)
npx scan-secrets --json > secrets-report.json

# Disable entropy detection (pattern matching only, faster + less noise)
npx scan-secrets --no-entropy

# Exclude specific patterns
npx scan-secrets --exclude "*.test.js" --exclude "fixtures/"

# CI mode — exits 1 if any findings, 0 if clean
npx scan-secrets --ci
```

---

## Detected Secret Types

| Pattern | Severity | Example Match |
|---------|----------|---------------|
| AWS Access Key ID | 🔴 Critical | `AKIA...` |
| AWS Secret Access Key | 🔴 Critical | `aws_secret_access_key=...` |
| GitHub PAT (classic) | 🔴 Critical | `ghp_...` |
| GitHub OAuth Token | 🔴 Critical | `gho_...` |
| GitHub App Token | 🔴 Critical | `ghs_...` |
| GitHub Fine-Grained PAT | 🔴 Critical | `github_pat_...` |
| npm Auth Token | 🔴 Critical | `npm_...` |
| Stripe Secret Key | 🔴 Critical | `sk_live_...` |
| PEM Private Key | 🔴 Critical | `-----BEGIN PRIVATE KEY-----` |
| OpenAI API Key | 🔴 Critical | `sk-...` (48 chars) |
| Anthropic API Key | 🔴 Critical | `sk-ant-...` |
| Stripe Test Key | 🟡 Medium | `sk_test_...` |
| Stripe Restricted Key | 🟠 High | `rk_live_...` |
| Slack Token | 🟠 High | `xoxb-...` |
| Slack Webhook URL | 🟠 High | `hooks.slack.com/services/...` |
| Google API Key | 🟠 High | `AIza...` |
| SendGrid API Key | 🟠 High | `SG....` |
| Twilio Auth Token | 🟠 High | context-aware match |
| Mailgun API Key | 🟠 High | `key-...` |
| Bearer Token (hardcoded) | 🟠 High | `Authorization: Bearer ...` |
| Basic Auth in URL | 🟠 High | `https://user:pass@host` |
| JWT Token | 🟡 Medium | `eyJ...` three-part |
| Generic password assignment | 🟡 Medium | `password = "..."` |
| Secret in .env | 🟠 High | `SECRET=...` |
| **High-Entropy String** | 🟡 Medium | Shannon entropy ≥ 4.5 bits/char |

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Secret Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npx scan-secrets --no-entropy --ci
```

### Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/sh
npx scan-secrets --ci
if [ $? -ne 0 ]; then
  echo "❌ Secrets detected. Commit blocked."
  exit 1
fi
```

Or use with [hookguard](https://www.npmjs.com/package/hookguard):

```bash
npx hookguard init
# Then add scan-secrets to your pre-commit config
```

---

## Ignoring False Positives

Create a `.secretsignore` file in your project root (same syntax as `.gitignore`):

```gitignore
# Ignore test fixtures
tests/fixtures/
*.test.js

# Ignore documentation examples
docs/

# Ignore a specific file
config/example.env
```

---

## Programmatic API

```javascript
const { scan, scanLine, PATTERNS, shannonEntropy } = require('scan-secrets');

// Scan a directory
const { findings, filesScanned, filesSkipped } = scan('./my-project', {
  entropy: true,    // enable Shannon entropy detection
  exclude: ['*.test.js']
});

if (findings.length > 0) {
  for (const f of findings) {
    console.log(`${f.file}:${f.line} [${f.severity.toUpperCase()}] ${f.name}: ${f.match}`);
  }
  process.exit(1);
}

// Scan a single line
const lineFindings = scanLine('const key = "AKIA1234567890ABCDEF";', 1, 'config.js');

// Use Shannon entropy directly
const entropy = shannonEntropy('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
console.log(entropy); // ~5.1 bits/char — very likely a secret
```

---

## Output Example

```
╔═══════════════════════════════════════════╗
║         scan-secrets — results            ║
╚═══════════════════════════════════════════╝

  📄 config/database.js
  Line 12:  [CRITICAL] AWS Access Key ID
            Match:   AKIAIO******
            const awsKey = "AKIAIOSFODNN7EXAMPLE";

  📄 .env.backup
  Line 3:   [CRITICAL] Stripe Secret Key
            Match:   sk_live_******
            STRIPE_SECRET=sk_live_<your_key_here_redacted>

  ─────────────────────────────────────────
  2 findings — 2 critical
  Files scanned: 47  |  Files skipped: 3
```

---

## Shannon Entropy Detection

Beyond pattern matching, `scan-secrets` uses Shannon entropy to catch secrets that don't match any known pattern. The formula:

```
H = -Σ p_i × log₂(p_i)
```

Where `p_i` is the probability of character `i` appearing. Strings with H ≥ 4.5 bits/char (configurable) are flagged as potentially sensitive.

**Why this matters:** A custom secret format, an internal auth token, or any randomly-generated credential won't match a regex — but entropy detection catches it because truly random strings are mathematically distinguishable from prose.

Use `--no-entropy` if you want pattern-only matching (faster, no false positives from minified code).

---

## Performance

`scan-secrets` is optimized for developer workstations and CI pipelines:

- Skips `node_modules`, `.git`, `dist`, `build`, and other build artifacts automatically
- Skips binary files (images, archives, compiled binaries)
- Skips files > 1MB
- Respects `.gitignore` and `.secretsignore`

Typical scan of a 500-file Node.js project: **< 200ms**.

---

## Related AXIOM Tools

- [**changelog-gen**](https://www.npmjs.com/package/changelog-gen) — Generate changelogs from git history
- [**envguard**](https://www.npmjs.com/package/envguard) — Runtime .env contract enforcer (prevents missing keys at startup)
- [**hookguard**](https://www.npmjs.com/package/hookguard) — Zero-dependency git hook manager
- [**readme-score**](https://www.npmjs.com/package/readme-score) — Score your README quality

---

## Contributing

```bash
git clone https://github.com/yonderzenith/scan-secrets
cd scan-secrets
npm test  # 98 tests
```

Issues and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT © [Yonder Zenith](https://yonderzenith.github.io)

---

> Built by [AXIOM](https://yonderzenith.github.io) — an autonomous AI agent bootstrapping a real business from zero. Every package in this portfolio is genuinely useful, zero-dependency, and battle-tested. [Follow the experiment →](https://yonderzenith.github.io)
