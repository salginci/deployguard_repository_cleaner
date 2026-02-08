# 💻 DeployGuard CLI Reference

Complete command-line interface reference for DeployGuard.

---

## Table of Contents

- [Installation](#installation)
- [Global Options](#global-options)
- [Commands](#commands)
  - [scan](#scan)
  - [clean](#clean)
  - [verify](#verify)
  - [remediate](#remediate)
  - [hooks](#hooks)
  - [report](#report)
- [Configuration](#configuration)
- [Exit Codes](#exit-codes)
- [Environment Variables](#environment-variables)

---

## Installation

```bash
# Using pip
pip install deployguard

# From source
git clone https://github.com/salginci/deployguard_repository_cleaner.git
cd deployguard_repository_cleaner
pip install -e .

# Check installation
deployguard --version
```

---

## Global Options

These options work with all commands:

```bash
--help, -h          Show help message and exit
--version, -v       Show version and exit
--verbose, -V       Enable verbose output
--quiet, -q         Suppress all output except errors
--config FILE       Path to custom config file (.deployguard.yml)
--no-color          Disable colored output
--log-file FILE     Write logs to file
--log-level LEVEL   Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
```

### Examples

```bash
# Show help
deployguard --help
deployguard scan --help

# Check version
deployguard --version

# Verbose output
deployguard scan local --path . --verbose

# Use custom config
deployguard scan local --path . --config my-config.yml

# Log to file
deployguard scan local --path . --log-file scan.log --log-level DEBUG
```

---

## Commands

## `scan`

Scan repositories for exposed secrets.

### Subcommands

#### `scan local`

Scan a local directory or repository.

**Syntax:**
```bash
deployguard scan local --path PATH [OPTIONS]
```

**Options:**

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `--path`, `-p` | PATH | Path to scan (required) | - |
| `--output`, `-o` | FILE | Output file for findings | `scan-results.json` |
| `--format`, `-f` | FORMAT | Output format: json, html, text | `json` |
| `--export-purge` | FILE | Export secrets to purge file | - |
| `--include` | PATTERN | Include files matching pattern | `*` |
| `--exclude` | PATTERN | Exclude files matching pattern | - |
| `--severity` | LEVEL | Minimum severity: low, medium, high, critical | `low` |
| `--types` | TYPES | Secret types to scan (comma-separated) | all |
| `--max-file-size` | SIZE | Skip files larger than SIZE (MB) | 10 |
| `--no-entropy` | FLAG | Disable entropy-based detection | False |
| `--threads` | NUM | Number of scanning threads | 4 |

**Examples:**

```bash
# Basic scan
deployguard scan local --path .

# Scan with custom output
deployguard scan local --path /path/to/project --output findings.json

# Export findings to HTML
deployguard scan local --path . --format html --output report.html

# Export purge file for cleaning
deployguard scan local --path . --export-purge secrets.txt

# Scan only specific file types
deployguard scan local --path . --include "*.js,*.py,*.java"

# Exclude directories
deployguard scan local --path . --exclude "**/node_modules/**,**/test/**"

# Scan only high-severity secrets
deployguard scan local --path . --severity high

# Scan for specific secret types
deployguard scan local --path . --types "aws_access_key,generic_password,jwt_token"

# Scan with more threads (faster)
deployguard scan local --path . --threads 8

# Skip large files
deployguard scan local --path . --max-file-size 5
```

**Output:**

```json
{
  "summary": {
    "total_findings": 15,
    "scan_time": 2.34,
    "files_scanned": 1234,
    "by_severity": {
      "critical": 0,
      "high": 10,
      "medium": 3,
      "low": 2
    },
    "by_type": {
      "password": 5,
      "generic_secret": 5,
      "aws_access_key": 3,
      "jwt_token": 2
    }
  },
  "findings": [
    {
      "type": "aws_access_key",
      "severity": "high",
      "file": "config/aws.py",
      "line": 12,
      "value": "AKIA****************",
      "pattern": "AWS Access Key",
      "entropy": 5.2,
      "context": "AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'"
    }
  ]
}
```

#### `scan remote`

Scan a remote repository without cloning.

**Syntax:**
```bash
deployguard scan remote --url URL [OPTIONS]
```

**Options:**

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `--url`, `-u` | URL | Repository URL (required) | - |
| `--branch`, `-b` | BRANCH | Branch to scan | `main` |
| `--token`, `-t` | TOKEN | Authentication token | - |
| `--depth` | NUM | Clone depth (shallow clone) | - |
| `--output`, `-o` | FILE | Output file for findings | `scan-results.json` |

**Examples:**

```bash
# Scan GitHub repository
deployguard scan remote --url https://github.com/user/repo

# Scan specific branch
deployguard scan remote --url https://github.com/user/repo --branch develop

# Scan with authentication
deployguard scan remote --url https://github.com/user/private-repo --token $GITHUB_TOKEN

# Shallow scan (faster)
deployguard scan remote --url https://github.com/user/repo --depth 1
```

---

## `clean`

Remove secrets from git history.

### Subcommands

#### `clean history`

Permanently remove secrets from git history using git-filter-repo.

⚠️ **WARNING**: This command rewrites git history. Always backup first!

**Syntax:**
```bash
deployguard clean history --path PATH [OPTIONS]
```

**Options:**

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `--path`, `-p` | PATH | Path to git repository (required) | - |
| `--purge-file`, `-f` | FILE | File containing secrets to purge | - |
| `--findings`, `-i` | FILE | Findings JSON file | - |
| `--execute`, `-e` | FLAG | Execute cleaning (dry-run without) | False |
| `--force` | FLAG | Force clean without confirmation | False |
| `--preserve-emails` | FLAG | Preserve commit author emails | True |
| `--preserve-dates` | FLAG | Preserve commit dates | True |
| `--replace-text` | TEXT | Replacement text for secrets | `***REMOVED***` |

**Examples:**

```bash
# Dry-run (preview what will be cleaned)
deployguard clean history --path repo.git

# Clean using findings file
deployguard clean history --path repo.git --findings findings.json --execute

# Clean using purge file
deployguard clean history --path repo.git --purge-file secrets.txt --execute

# Force clean without confirmation
deployguard clean history --path repo.git --execute --force

# Custom replacement text
deployguard clean history --path repo.git --execute --replace-text "[REDACTED]"
```

**Workflow:**

```bash
# 1. Clone repository as mirror
git clone --mirror https://github.com/user/repo.git repo.git

# 2. Scan for secrets
deployguard scan local --path repo.git --output findings.json

# 3. Preview cleaning (dry-run)
deployguard clean history --path repo.git --findings findings.json

# 4. Execute cleaning (⚠️ REWRITES HISTORY!)
deployguard clean history --path repo.git --findings findings.json --execute

# 5. Verify secrets are removed
deployguard verify --path repo.git

# 6. Push to remote (⚠️ FORCE PUSH!)
cd repo.git
git push --force --all
git push --force --tags
```

---

## `verify`

Verify that secrets have been removed from git history.

**Syntax:**
```bash
deployguard verify --path PATH [OPTIONS]
```

**Options:**

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `--path`, `-p` | PATH | Path to git repository (required) | - |
| `--original-findings`, `-o` | FILE | Original findings file (before cleaning) | - |
| `--output`, `-O` | FILE | Output verification report | - |
| `--branch`, `-b` | BRANCH | Branch to verify | all |

**Examples:**

```bash
# Verify all branches
deployguard verify --path repo.git

# Verify and compare with original findings
deployguard verify --path repo.git --original-findings findings.json

# Verify specific branch
deployguard verify --path repo.git --branch main

# Export verification report
deployguard verify --path repo.git --output verification-report.json
```

**Output:**

```json
{
  "status": "clean",
  "secrets_found": 0,
  "original_secrets": 15,
  "removed": 15,
  "remaining": 0,
  "branches_verified": ["main", "develop", "feature/login"],
  "verification_time": "2024-01-15T10:30:00Z"
}
```

---

## `remediate`

Assist with secret remediation and code updates.

### Subcommands

#### `remediate extract`

Extract secrets from findings to environment variables.

**Syntax:**
```bash
deployguard remediate extract --findings FILE [OPTIONS]
```

**Options:**

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `--findings`, `-f` | FILE | Findings JSON file (required) | - |
| `--output`, `-o` | FILE | Output env file | `.env.example` |
| `--format` | FORMAT | Format: env, yaml, json | `env` |
| `--prefix` | TEXT | Variable name prefix | - |

**Examples:**

```bash
# Extract to .env file
deployguard remediate extract --findings findings.json --output .env.example

# Extract to YAML
deployguard remediate extract --findings findings.json --output secrets.yml --format yaml

# Add prefix to variables
deployguard remediate extract --findings findings.json --prefix APP_
```

**Output (.env):**

```env
# AWS Credentials
AWS_ACCESS_KEY=AKIA****************
AWS_SECRET_KEY=****************

# Database
DB_PASSWORD=****************
DB_CONNECTION_STRING=****************

# API Keys
STRIPE_API_KEY=sk_test_****************
SENDGRID_API_KEY=SG.****************
```

#### `remediate update-code`

Update code to use environment variables.

**Syntax:**
```bash
deployguard remediate update-code --findings FILE --language LANG [OPTIONS]
```

**Options:**

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `--findings`, `-f` | FILE | Findings JSON file (required) | - |
| `--language`, `-l` | LANG | Language: js, py, java, go, etc. | - |
| `--dry-run` | FLAG | Preview changes without applying | False |
| `--backup` | FLAG | Create backup files (.bak) | True |

**Examples:**

```bash
# Update JavaScript code
deployguard remediate update-code --findings findings.json --language javascript

# Preview changes (dry-run)
deployguard remediate update-code --findings findings.json --language python --dry-run

# Update without backup
deployguard remediate update-code --findings findings.json --language java --no-backup
```

#### `remediate github-secrets`

Generate GitHub Actions secrets setup commands.

**Syntax:**
```bash
deployguard remediate github-secrets --findings FILE --repo REPO [OPTIONS]
```

**Options:**

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `--findings`, `-f` | FILE | Findings JSON file (required) | - |
| `--repo`, `-r` | REPO | GitHub repository (user/repo) | - |
| `--output`, `-o` | FILE | Output shell script | `setup-secrets.sh` |

**Examples:**

```bash
# Generate secrets setup script
deployguard remediate github-secrets --findings findings.json --repo user/repo

# This generates: setup-secrets.sh
```

**Output (setup-secrets.sh):**

```bash
#!/bin/bash
# GitHub Secrets Setup
# Run: gh secret set SECRET_NAME < value.txt

echo "Setting up GitHub Secrets for user/repo..."

# AWS Credentials
echo "AKIAIOSFODNN7EXAMPLE" | gh secret set AWS_ACCESS_KEY --repo user/repo
echo "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" | gh secret set AWS_SECRET_KEY --repo user/repo

# Database
echo "MyS3cr3tP@ssw0rd!" | gh secret set DB_PASSWORD --repo user/repo

echo "✅ All secrets configured!"
```

---

## `hooks`

Manage git hooks for preventing secret commits.

### Subcommands

#### `hooks install`

Install pre-commit hook to prevent secret commits.

**Syntax:**
```bash
deployguard hooks install [OPTIONS]
```

**Options:**

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `--path`, `-p` | PATH | Git repository path | `.` |
| `--strict` | FLAG | Block commit if secrets found | False |
| `--warn-only` | FLAG | Warn but allow commit | True |

**Examples:**

```bash
# Install hook (warn only)
deployguard hooks install

# Install strict hook (block commits)
deployguard hooks install --strict

# Install in specific repository
deployguard hooks install --path /path/to/repo
```

#### `hooks uninstall`

Remove pre-commit hook.

**Syntax:**
```bash
deployguard hooks uninstall [OPTIONS]
```

**Examples:**

```bash
# Uninstall hook
deployguard hooks uninstall

# Uninstall from specific repository
deployguard hooks uninstall --path /path/to/repo
```

---

## `report`

Generate reports from findings.

**Syntax:**
```bash
deployguard report --findings FILE [OPTIONS]
```

**Options:**

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `--findings`, `-f` | FILE | Findings JSON file (required) | - |
| `--format` | FORMAT | Format: html, pdf, markdown, csv | `html` |
| `--output`, `-o` | FILE | Output report file | `report.html` |
| `--template` | FILE | Custom report template | - |
| `--include-context` | FLAG | Include code context | True |

**Examples:**

```bash
# Generate HTML report
deployguard report --findings findings.json --format html --output report.html

# Generate PDF report
deployguard report --findings findings.json --format pdf --output report.pdf

# Generate markdown report
deployguard report --findings findings.json --format markdown --output REPORT.md

# Generate CSV for spreadsheet
deployguard report --findings findings.json --format csv --output findings.csv

# Use custom template
deployguard report --findings findings.json --template custom-template.html
```

---

## Configuration

### Config File (.deployguard.yml)

Create `.deployguard.yml` in your project root or home directory:

```yaml
# Secret Detection Settings
secret_detection:
  min_entropy: 5.0
  min_length: 16
  max_file_size_mb: 10
  
# File Exclusions
exclude_files:
  - "**/*.test.js"
  - "**/*.spec.ts"
  - "**/fixtures/**"
  - "**/mocks/**"
  - "**/*.ejs"
  
exclude_dirs:
  - node_modules
  - .git
  - dist
  - build
  - coverage
  - __pycache__
  
# File Inclusions (if specified, only these are scanned)
include_files:
  - "**/*.js"
  - "**/*.py"
  - "**/*.java"
  
# Custom Patterns
patterns:
  - name: custom_api_key
    pattern: 'MYAPP_KEY_[A-Za-z0-9]{32}'
    severity: high
    description: "Custom API key pattern"
    
  - name: custom_token
    pattern: 'tkn_[A-Za-z0-9]{40}'
    severity: critical
    description: "Custom token pattern"

# Severity Thresholds
severity:
  aws_access_key: critical
  generic_password: high
  jwt_token: medium
  url: low

# Remediation Settings
remediation:
  env_file_format: dotenv  # dotenv, yaml, json
  backup_files: true
  variable_prefix: ""
  
# Reporting
reporting:
  format: html
  include_context: true
  context_lines: 3
  
# Performance
performance:
  threads: 4
  max_file_size_mb: 10
  enable_cache: true
```

### Config File Locations

DeployGuard looks for configuration in this order:

1. `--config` option (if provided)
2. `.deployguard.yml` in current directory
3. `.deployguard.yml` in project root
4. `~/.deployguard.yml` in home directory
5. Default built-in configuration

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (no secrets found or operation successful) |
| 1 | Secrets found |
| 2 | Configuration error |
| 3 | Runtime error |
| 4 | Permission error |
| 5 | Git error |
| 10 | Validation error |

**Usage:**

```bash
deployguard scan local --path .
if [ $? -eq 0 ]; then
  echo "✅ No secrets found"
else
  echo "❌ Secrets detected!"
  exit 1
fi
```

---

## Environment Variables

DeployGuard respects these environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `DEPLOYGUARD_CONFIG` | Path to config file | `.deployguard.yml` |
| `DEPLOYGUARD_LOG_LEVEL` | Log level | `INFO` |
| `DEPLOYGUARD_THREADS` | Number of threads | `4` |
| `DEPLOYGUARD_NO_COLOR` | Disable colored output | `false` |
| `GITHUB_TOKEN` | GitHub API token | - |
| `GITLAB_TOKEN` | GitLab API token | - |
| `BITBUCKET_TOKEN` | Bitbucket API token | - |

**Examples:**

```bash
# Set log level
export DEPLOYGUARD_LOG_LEVEL=DEBUG
deployguard scan local --path .

# Disable colors
export DEPLOYGUARD_NO_COLOR=true
deployguard scan local --path .

# Use custom config
export DEPLOYGUARD_CONFIG=/path/to/config.yml
deployguard scan local --path .

# Scan with GitHub token
export GITHUB_TOKEN=ghp_xxxxxxxxxxxx
deployguard scan remote --url https://github.com/user/private-repo
```

---

## Complete Examples

### Example 1: Full Workflow (Scan → Clean → Verify)

```bash
#!/bin/bash
set -e

# 1. Clone repository
git clone --mirror https://github.com/user/repo.git repo.git
cd repo.git

# 2. Scan for secrets
deployguard scan local --path . --output ../findings.json

# 3. Review findings
cat ../findings.json | jq '.summary'

# 4. Clean history (dry-run first)
deployguard clean history --path . --findings ../findings.json

# 5. Execute cleaning (⚠️ REWRITES HISTORY!)
read -p "Continue with cleaning? (yes/no): " confirm
if [ "$confirm" = "yes" ]; then
  deployguard clean history --path . --findings ../findings.json --execute
fi

# 6. Verify secrets are removed
deployguard verify --path . --original-findings ../findings.json

# 7. Push to remote (⚠️ FORCE PUSH!)
read -p "Force push to remote? (yes/no): " confirm
if [ "$confirm" = "yes" ]; then
  git push --force --all
  git push --force --tags
fi

echo "✅ Complete!"
```

### Example 2: CI/CD Integration (GitHub Actions)

```yaml
name: Secret Detection
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install DeployGuard
        run: pip install deployguard
      
      - name: Scan for secrets
        run: |
          deployguard scan local --path . --output findings.json --severity high
          
      - name: Upload findings
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: security-findings
          path: findings.json
      
      - name: Block PR if secrets found
        run: |
          if [ $(cat findings.json | jq '.summary.total_findings') -gt 0 ]; then
            echo "❌ Secrets detected! PR blocked."
            exit 1
          fi
```

### Example 3: Pre-commit Hook

```bash
# Install pre-commit hook
deployguard hooks install --strict

# Now commits with secrets will be blocked
git add .
git commit -m "Add feature"
# ❌ Commit blocked! Secrets detected in file.py
```

---

## Getting Help

```bash
# General help
deployguard --help

# Command-specific help
deployguard scan --help
deployguard clean --help
deployguard verify --help

# Show all commands
deployguard --help

# Show version
deployguard --version
```

---

**Need more help?** See [README.md](README.md) or visit [https://docs.deployguard.io](https://docs.deployguard.io)
