e got this error# 🛡️ DeployGuard Repository Cleaner

<p align="center">
  <strong>The Complete Secret Detection & Remediation Tool</strong><br>
  <em>Gitleaks + BFG Repo-Cleaner + truffleHog — All in One</em>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#commands">Commands</a> •
  <a href="#pre-commit-hook">Pre-Commit Hook</a> •
  <a href="#verified-secrets">Verified Secrets</a> •
  <a href="#auto-remediation">Auto-Remediation</a> •
  <a href="#cicd-integration">CI/CD</a>
</p>

---

## 🎯 What is DeployGuard?

DeployGuard is a **100% custom-built** secret detection and remediation tool that combines the best features of:

| Tool | What it does | DeployGuard |
|------|--------------|-------------|
| **Gitleaks** | Detects secrets in code | ✅ 961 patterns |
| **truffleHog** | Most comprehensive + verified secrets | ✅ 961 patterns + verification |
| **BFG Repo-Cleaner** | Removes secrets from git history | ✅ Built-in |
| **Manual work** | Replace secrets with env vars | ✅ **Auto-remediation** |

### Key Features

- 🔍 **961 Detection Patterns** — Industry-leading coverage matching truffleHog
- ✅ **Verified Secrets** — Test if detected secrets are actually active (like truffleHog!)
- 🛡️ **Pre-Commit Hook** — Block commits containing secrets
- 🔄 **Auto-Remediation** — Replace hardcoded secrets with environment variables
- 🌐 **Language-Aware** — Generates correct syntax for Python, JavaScript, Go, Java, etc.
- 📜 **Git History Cleaning** — Remove secrets from entire git history
- 📊 **Multiple Export Formats** — JSON, CSV, .env.template, secrets_to_purge.txt
- 🔌 **GitHub/Bitbucket Integration** — Scan remote repositories via API

---

## 📥 Installation

### System-Wide Installation (Recommended)

Install once, use in any repository:

```bash
# Option 1: Install from PyPI (recommended)
pip install deployguard-repo-guard

# Option 2: Install from source
git clone https://github.com/salginci/deployguard_repository_cleaner.git
cd deployguard_repository_cleaner
pip install -e .
```

After installation, `deployguard` is available globally:

```bash
# Works from any directory
cd ~/my-project
deployguard scan local --path .
```

### Per-Repository Installation

If you prefer project-level isolation:

```bash
cd ~/my-project
python -m venv venv
source venv/bin/activate
pip install deployguard-repo-guard
```

### Docker Installation

```bash
docker pull deployguard/deployguard:latest
docker run -v $(pwd):/repo deployguard/deployguard scan local --path /repo
```

---

## ⚡ Quick Start

### 1. Scan a Repository

```bash
# Scan current directory
deployguard scan local --path .

# Scan with output to JSON
deployguard scan local --path . --output findings.json

# Scan including git history
deployguard scan local --path . --include-history
```

### 2. Install Pre-Commit Hook

```bash
# Install hook (blocks commits with secrets)
deployguard hooks install

# Check status
deployguard hooks status

# Test the hook
deployguard hooks test
```

### 3. Auto-Fix Detected Secrets

```bash
# Preview what would change (dry run)
deployguard remediate auto --path . --preview

# Actually fix the code
deployguard remediate auto --path . --execute
```

---

## 📖 Commands Reference

### `deployguard scan` — Detect Secrets

```bash
# Basic scan of current directory
deployguard scan local --path .

# Scan with custom patterns file
deployguard scan local --path . --patterns my-patterns.yaml

# Scan only critical/high severity
deployguard scan local --path . --min-severity high

# Export findings
deployguard scan local --path . --output results.json        # JSON format
deployguard scan local --path . --output results.csv         # CSV format
deployguard scan local --path . --export-purge secrets.txt   # For git history cleaning
deployguard scan local --path . --export-env .env.template   # Environment template

# Interactive mode (select which findings to process)
deployguard scan local --path . --interactive

# Scan including git history
deployguard scan local --path . --include-history
```

### `deployguard verify` — Verify Active Secrets

```bash
# Verify all secrets in current directory
deployguard verify .

# Only show active (valid) secrets
deployguard verify --only-active

# Only show inactive (revoked) secrets  
deployguard verify --only-inactive

# Output as JSON
deployguard verify -o json

# Output as table (default)
deployguard verify -o table

# Custom timeout (seconds) and concurrency
deployguard verify -t 30 -c 10

# Verify with custom patterns
deployguard verify . --config custom-patterns.yaml
```

**What it does:**
- Scans for secrets in your codebase
- Makes API calls to verify if each secret is active
- Reports which secrets need immediate rotation
- Exits with code 1 if active secrets are found

### `deployguard hooks` — Pre-Commit Protection

```bash
# Install pre-commit hook in current repo
deployguard hooks install

# Install in specific repo
deployguard hooks install --path /path/to/repo

# Check if hook is installed
deployguard hooks status

# Manually test the hook (without committing)
deployguard hooks test

# Remove the hook
deployguard hooks uninstall
```

**How it works:**
1. Run `deployguard hooks install` once per repository
2. Every `git commit` automatically scans staged files
3. If secrets are found, commit is blocked with details
4. Fix the issues or use `git commit --no-verify` to bypass (not recommended)

### `deployguard remediate` — Auto-Fix Secrets

```bash
# Preview changes (dry run)
deployguard remediate auto --path . --preview

# Apply changes
deployguard remediate auto --path . --execute

# Use existing scan results
deployguard remediate from-json --findings findings.json --execute

# Preview specific file
deployguard remediate preview --file config.py
```

**What it does:**
- Scans for hardcoded secrets
- Replaces them with environment variable references
- Generates `.env` file with extracted values
- Uses correct syntax for each language:

| Language | Before | After |
|----------|--------|-------|
| Python | `API_KEY = "sk-123"` | `API_KEY = os.environ.get('API_KEY')` |
| JavaScript | `const API_KEY = "sk-123"` | `const API_KEY = process.env.API_KEY` |
| Bash | `API_KEY="sk-123"` | `API_KEY="${API_KEY}"` |
| Go | `apiKey := "sk-123"` | `apiKey := os.Getenv("API_KEY")` |
| Java | `String apiKey = "sk-123"` | `String apiKey = System.getenv("API_KEY")` |

### `deployguard clean` — Git History Cleaning

Removes secrets from entire git history with **interactive review** to avoid false positives.

```bash
# Clone repo as mirror first
git clone --mirror https://github.com/owner/repo.git repo.git

# Preview what would be cleaned (dry run)
deployguard clean history --path repo.git

# Clean with interactive review (DEFAULT - recommended)
# You'll review each detected secret one by one
deployguard clean history --path repo.git --execute

# Skip interactive review (use with caution - may include false positives)
deployguard clean history --path repo.git --execute --auto-approve

# Save reports to specific directory
deployguard clean history --path repo.git --execute --report-dir /tmp/reports

# Force push cleaned history
cd repo.git
git push --force --all
git push --force --tags
```

#### Interactive Review Mode

When running without `--auto-approve`, you'll review each detection:

```
[1/27] api_key (high)
   📄 Value: AIzaSyB1234567890abcdef...
   🏷️  Env Var: DG_GOOGLE_API_KEY_A1B2
   ➡️  Will replace with: ***REMOVED***
   📁 Found in 3 file(s): config.xml, build.gradle, ...
   ⚠️  POSSIBLE FALSE POSITIVE: Looks like code/variable name

   Include in cleanup? [y/n/a/s/q]: 
```

Commands:
- `y` - Yes, include this secret in cleanup
- `n` - No, skip (mark as false positive)
- `a` - Include this and ALL remaining
- `s` - Skip this and ALL remaining
- `q` - Quit/cancel

Your feedback is anonymously sent to improve false positive detection!

### `deployguard auth` — Platform Authentication

```bash
# Set GitHub token
deployguard auth --github-token ghp_xxxxxxxxxxxx

# Set from environment variable
export GITHUB_TOKEN=ghp_xxxxxxxxxxxx
deployguard auth --github-token-env GITHUB_TOKEN

# Check authentication status
deployguard auth status
```

### `deployguard report` — View Past Scans

```bash
# Show latest scan report
deployguard report --latest

# Show specific scan
deployguard report --scan-id abc123
```

---

## 🪝 Pre-Commit Hook

The pre-commit hook is the **#1 way to prevent secrets from ever entering your repository**.

### Installation

```bash
cd your-repo
deployguard hooks install
```

### What Happens When You Commit

```
$ git add .
$ git commit -m "Add new feature"

🔍 DeployGuard: Scanning staged files for secrets...

🚨 SECRETS DETECTED IN STAGED FILES!
============================================================

1. 🔴 [CRITICAL] stripe_api_key
   📁 File: config.py:15
   🏷️  Variable: STRIPE_KEY
   🔑 Value: sk_l****4567

============================================================
❌ Found 1 secret(s) in staged files!

💡 To fix:
   1. Remove secrets from your code
   2. Use environment variables instead
   3. Run: deployguard remediate auto --path .

❌ Commit blocked: Secrets detected in staged files!
```

### Bypassing the Hook (Emergency Only)

```bash
git commit --no-verify -m "Emergency commit"
```

⚠️ **Warning:** Only use this if you're absolutely sure the detection is a false positive.

---

## ✅ Verified Secrets

Like truffleHog, DeployGuard can **verify if detected secrets are actually active** by making API calls to the respective services. This dramatically reduces false positives and helps prioritize remediation.

### Basic Usage

```bash
# Verify all detected secrets in current directory
deployguard verify .

# Only show active (valid) secrets
deployguard verify --only-active

# Output as JSON
deployguard verify -o json

# Custom timeout and concurrency
deployguard verify -t 30 -c 10
```

### Verification Status

| Status | Icon | Meaning |
|--------|------|---------|
| `VERIFIED_ACTIVE` | ✓ | Secret is **valid and working** — immediate action required! |
| `VERIFIED_INACTIVE` | ✗ | Secret is invalid/revoked — lower priority |
| `UNVERIFIED` | ? | Could not verify (unsupported type or needs more context) |
| `ERROR` | ! | Verification failed due to error |
| `RATE_LIMITED` | ⏱ | API rate limit hit during verification |

### Example Output

```
$ deployguard verify ./src --only-active

🔍 Scanning ./src for secrets...
📋 Found 5 potential secrets. Verifying...

──────────────────────────────────────────────────────────────────────
📁 src/config.py:15
   Type: github_token
   Value: ghp_************************************xyz
   Status: ✓ ACTIVE
   Message: GitHub token is valid (user: john-doe)
   Details: {"user": "john-doe", "scopes": "repo,read:org"}
──────────────────────────────────────────────────────────────────────
📁 src/payment.py:42
   Type: stripe_api_key
   Value: sk_l****************************4567
   Status: ✓ ACTIVE
   Message: Stripe API key is valid
   Details: {"livemode": true}
──────────────────────────────────────────────────────────────────────

📊 Verification Summary:
   Total secrets found: 5
   ⚠️  ACTIVE (valid): 2
   ✗  Inactive (revoked): 1
   ?  Unverified: 2

🚨 CRITICAL: 2 active secret(s) detected! Rotate these immediately!
```

### Supported Services for Verification

DeployGuard can verify secrets for **40+ services**:

| Category | Services |
|----------|----------|
| **Version Control** | GitHub (PAT, OAuth, App), GitLab, Bitbucket |
| **Cloud Providers** | AWS*, Heroku, DigitalOcean, Vercel, Netlify, Fly.io, Cloudflare |
| **AI/ML** | OpenAI, Anthropic, HuggingFace |
| **Payment** | Stripe |
| **Communication** | Slack (Bot, User tokens), Discord (Webhook, Bot) |
| **Email** | SendGrid, Mailchimp, Mailgun |
| **Monitoring** | Datadog, New Relic, Sentry* |
| **Productivity** | Notion, Airtable, Asana, Linear |
| **Package Registries** | NPM, PyPI* |
| **Secrets Management** | Doppler |

*\* Format validation only (full verification requires additional context)*

### CI/CD Integration

Add verification to your pipeline:

```yaml
# GitHub Actions
- name: Verify Secrets
  run: |
    deployguard verify . --only-active -o json > verification.json
    if [ -s verification.json ]; then
      echo "🚨 Active secrets detected!"
      exit 1
    fi
```

---

## 🔄 Auto-Remediation

DeployGuard can automatically replace hardcoded secrets with secure environment variable references.

### Example Workflow

```bash
# 1. Scan and find secrets
deployguard scan local --path . --output findings.json

# 2. Preview what would change
deployguard remediate auto --path . --preview

# 3. Apply the fixes
deployguard remediate auto --path . --execute

# 4. Review generated .env file
cat .env

# 5. Add .env to .gitignore
echo ".env" >> .gitignore
```

### Before & After

**Before (config.py):**
```python
DB_PASSWORD = "super_secret_123"
API_KEY = "sk-1234567890abcdef"
```

**After (config.py):**
```python
DB_PASSWORD = os.environ.get('DB_PASSWORD')
API_KEY = os.environ.get('API_KEY')
```

**Generated (.env):**
```
DB_PASSWORD="super_secret_123"
API_KEY="sk-1234567890abcdef"
```

---

## 🔌 CI/CD Integration

### GitHub Actions

Create `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for complete scan

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install DeployGuard
        run: |
          pip install deployguard-repo-guard

      - name: Run Secret Scan
        run: |
          deployguard scan local --path . --min-severity high --output results.json

      - name: Upload Results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-scan-results
          path: results.json

      - name: Fail on Critical Secrets
        run: |
          if grep -q '"severity": "critical"' results.json; then
            echo "❌ Critical secrets found!"
            exit 1
          fi
```

### GitLab CI

Create `.gitlab-ci.yml`:

```yaml
secret-scan:
  image: python:3.11
  stage: test
  script:
    - pip install deployguard-repo-guard
    - deployguard scan local --path . --min-severity high --output results.json
  artifacts:
    reports:
      security: results.json
    when: always
```

### Pre-Commit Framework Integration

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: deployguard
        name: DeployGuard Secret Scanner
        entry: deployguard hooks protect
        language: system
        pass_filenames: false
```

---

## 📊 Detection Patterns

DeployGuard includes **961 detection patterns** covering:

| Category | Examples |
|----------|----------|
| **Cloud Providers** | AWS Access Keys, GCP API Keys, Azure Secrets, Alibaba, DigitalOcean, Heroku |
| **Version Control** | GitHub PAT, GitLab Tokens, Bitbucket |
| **AI/ML Services** | OpenAI, Anthropic, Cohere, HuggingFace, Replicate, Weights & Biases |
| **Payment Services** | Stripe, Square, PayPal, Plaid, Braintree, Adyen |
| **Communication** | Slack, Discord, Twilio, SendGrid, Mailchimp, Mailgun |
| **Databases** | MongoDB, PostgreSQL, MySQL, Redis, PlanetScale, Supabase |
| **CI/CD** | Travis CI, CircleCI, Netlify, Vercel, GitHub Actions |
| **Infrastructure** | Terraform, Vault, Doppler, Pulumi, Heroku, Kubernetes |
| **Monitoring** | Datadog, New Relic, Sentry, Grafana, PagerDuty |
| **Package Registries** | npm, PyPI, RubyGems, Docker Hub |
| **Cryptographic** | RSA Keys, SSH Keys, PGP, Age, JWT |
| **Generic** | API Keys, Passwords, Bearer Tokens, Connection Strings |

### Custom Patterns

Create your own patterns in YAML:

```yaml
# my-patterns.yaml
patterns:
  - name: "Internal API Key"
    pattern: 'INTERNAL_[A-Z]+_KEY\s*=\s*[''"]([a-zA-Z0-9]{32})[''"]'
    secret_type: "api_key"
    severity: "critical"
    description: "Internal API Key detected"
```

Use with:

```bash
deployguard scan local --path . --patterns my-patterns.yaml
```

---

## 🆚 Comparison with Other Tools

| Feature | DeployGuard | truffleHog | Gitleaks | detect-secrets | git-secrets | BFG |
|---------|:-----------:|:----------:|:--------:|:--------------:|:-----------:|:---:|
| **Detection Patterns** | **961** | 800+ | 150+ | 30+ | 10+ | ❌ |
| **Verified Secrets** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Pre-Commit Hook** | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Git History Scan** | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| **Git History Clean** | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Auto-Remediation** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Language-Aware Fix** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **.env Generation** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Entropy Detection** | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| **Custom Patterns** | ✅ YAML | ❌ | ✅ TOML | ✅ | ✅ | ❌ |
| **GitHub/Bitbucket API** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **License** | MIT | AGPL-3.0 | MIT | Apache-2.0 | Apache-2.0 | GPL |

### Why DeployGuard?

1. **Most Comprehensive**: 961 patterns — more than any other tool
2. **Verified Secrets**: Know which secrets are actually active (like truffleHog)
3. **Auto-Remediation**: Automatically replace secrets with env vars (unique feature!)
4. **All-in-One**: Detection + Verification + Remediation + History Cleaning
5. **MIT License**: Use freely in commercial projects (unlike truffleHog's AGPL)

---

## ❓ FAQ

### Does DeployGuard need to be installed in every repository?

**No.** DeployGuard is installed **system-wide** (once per machine). You can use it in any repository:

```bash
# Install once
pip install deployguard-repo-guard

# Use anywhere
cd ~/project-a && deployguard scan local --path .
cd ~/project-b && deployguard scan local --path .
```

The **pre-commit hook** needs to be installed per-repository:

```bash
cd ~/project-a && deployguard hooks install
cd ~/project-b && deployguard hooks install
```

### What's the difference between scanning and the pre-commit hook?

| Aspect | `deployguard scan` | `deployguard hooks` |
|--------|-------------------|---------------------|
| When | Manual, on-demand | Automatic, every commit |
| Scope | Entire codebase | Only staged files |
| Purpose | Audit existing code | Prevent new secrets |
| Speed | Slower (full scan) | Fast (staged only) |

### Can I use DeployGuard with existing pre-commit hooks?

Yes! If you have an existing pre-commit hook:

```bash
# Backup existing hook
cp .git/hooks/pre-commit .git/hooks/pre-commit.backup

# Install DeployGuard hook
deployguard hooks install --force

# Manually merge if needed
```

Or use the pre-commit framework (`.pre-commit-config.yaml`) for multiple hooks.

### How do I reduce false positives?

1. **Use allowlists** in your patterns file:
   ```yaml
   allowlist:
     - 'example\.com'
     - 'localhost'
   ```

2. **Increase minimum severity:**
   ```bash
   deployguard scan local --path . --min-severity high
   ```

3. **Use `.deployguardignore`** file:
   ```
   # Ignore test fixtures
   tests/fixtures/
   # Ignore specific file
   docs/examples/fake-secrets.md
   ```

### Does DeployGuard work offline?

Yes! All scanning and remediation works completely offline. 

GitHub/Bitbucket integration requires internet only if you're scanning remote repositories.

---

## 🛠️ Development

### Run from Source

```bash
git clone https://github.com/salginci/deployguard_repository_cleaner.git
cd deployguard_repository_cleaner

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run CLI
python -m deployguard.cli.main --help
```

### Project Structure

```
deployguard/
├── cli/                    # CLI commands
│   ├── main.py            # Entry point
│   ├── scan.py            # Scan commands
│   ├── hooks.py           # Pre-commit hook
│   ├── remediate.py       # Auto-fix
│   ├── clean.py           # History cleaning
│   └── report.py          # Reporting
├── core/                   # Core logic
│   ├── scanner.py         # Pattern matching
│   ├── remediator.py      # Code replacement
│   ├── history_cleaner.py # Git history
│   └── models.py          # Data models
├── platforms/              # Platform adapters
│   ├── github_adapter.py
│   └── bitbucket_adapter.py
└── config/
    └── secret_patterns.yaml  # 150+ patterns
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [API Architecture](docs/API_ARCHITECTURE.md) | Full API v2 architecture with Kubernetes deployment |
| [Database Guide](docs/DATABASE_GUIDE.md) | Database schema, migrations, and Kubernetes setup |
| [Secrets Management](docs/SECRETS_MANAGEMENT.md) | How to inject secrets in Kubernetes deployments |
| [Feedback System](docs/FEEDBACK_SYSTEM.md) | ML feedback collection for false positive improvement |
| [Quality Improvement Playbook](docs/QUALITY_IMPROVEMENT_PLAYBOOK.md) | Step-by-step guide for improving detection quality |
| [CLI Guide](CLI_GUIDE.md) | Complete CLI reference |
| [Remediation Guide](REMEDIATION_GUIDE.md) | Auto-remediation features |
| [False Positive Reduction](FALSE_POSITIVE_REDUCTION.md) | How to reduce false positives |

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

## 🙏 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

---

<p align="center">
  Made with ❤️ for the security-conscious developer
</p>
