# 🛡️ DeployGuard CLI - Quick Start Guide

## ✅ CLI Successfully Created!

The DeployGuard CLI is now installed and ready to use with the following commands:

---

## 📦 Installation

```bash
cd /Users/salginci/Source/GITHUB/deployguard_repository_cleaner
source venv/bin/activate
pip install -e .
```

✅ **CLI command available**: `deployguard`

---

## 🚀 Available Commands

### 1. Authentication Management

Configure credentials for GitHub and BitBucket:

```bash
# Configure GitHub token
deployguard auth configure --github-token ghp_YOUR_TOKEN_HERE

# Configure BitBucket credentials
deployguard auth configure --bitbucket-username your-email@example.com --bitbucket-password YOUR_APP_PASSWORD

# Check authentication status
deployguard auth status

# View configuration (sanitized)
deployguard auth show

# Clear all credentials
deployguard auth clear
```

**Configuration stored at**: `~/.deployguard/config.json`

---

### 2. Scan Commands

#### Scan Local Directory or File

```bash
# Basic scan
deployguard scan local /path/to/project

# Scan with severity filter
deployguard scan local /path/to/project --severity high

# Save report as JSON
deployguard scan local /path/to/project --output report.json --format json

# Save report as CSV
deployguard scan local /path/to/project --output report.csv --format csv

# Scan single file
deployguard scan local /path/to/file.py --output finding.json --format json
```

**Options**:
- `--output`, `-o`: Output file path
- `--format`, `-f`: Output format (`text`, `json`, `csv`)
- `--severity`: Filter by severity (`all`, `critical`, `high`, `medium`, `low`)

#### Scan Remote Repository (Requires Authentication)

```bash
# Scan GitHub repository
deployguard scan repo owner/repository-name

# Scan BitBucket repository
deployguard scan repo workspace/repository-name --platform bitbucket

# Scan with options
deployguard scan repo owner/repo --severity critical --output report.json --format json
```

---

### 3. Report Commands

```bash
# Show saved report
deployguard report show report.json

# Show report with filters
deployguard report show report.json --severity critical
deployguard report show report.json --type AWS_ACCESS_KEY

# View statistics
deployguard report stats report.json

# Convert report format
deployguard report convert report.json html --output report.html
deployguard report convert report.json csv --output report.csv
```

---

## 💡 Usage Examples

### Example 1: Quick Local Scan

```bash
# Scan current directory for critical secrets
deployguard scan local . --severity critical
```

**Output**:
```
🔍 Scanning: .
============================================================

📊 SCAN RESULTS
============================================================
Files Scanned: 45
Total Findings: 3
Duration: 0.82s

⚠️  FINDINGS:

CRITICAL Severity: 3
  • AWS_ACCESS_KEY
    File: config/prod.py:15
    Value: AKIA****************MPLE
    Variable: AWS_ACCESS_KEY_ID
  ...
```

### Example 2: Scan & Save JSON Report

```bash
deployguard scan local ~/projects/my-app \
  --severity high \
  --output ~/security-report.json \
  --format json
```

### Example 3: Scan GitHub Repository

```bash
# First, configure GitHub token
deployguard auth configure --github-token ghp_xxxxxxxxxxxxx

# Then scan
deployguard scan repo myorg/my-repo --output github-scan.json --format json
```

### Example 4: View Report Statistics

```bash
deployguard report stats security-report.json
```

**Output**:
```
📊 Report Statistics
============================================================
Scan ID: a1b2c3d4-...
Scan Date: 2026-02-03T18:30:00
Files Scanned: 142
Total Findings: 23
Duration: 2.45s

By Severity:
  CRITICAL: 5
  HIGH: 12
  MEDIUM: 6

By Secret Type:
  AWS_ACCESS_KEY: 8
  GITHUB_TOKEN: 5
  API_KEY: 4
  ...
```

---

## 🎯 Common Workflows

### Pre-Commit Security Check

```bash
#!/bin/bash
# Add to .git/hooks/pre-commit

deployguard scan local . --severity high --output /tmp/scan.json --format json

if [ $(jq '.total_findings' /tmp/scan.json) -gt 0 ]; then
  echo "❌ Secrets detected! Commit blocked."
  deployguard report show /tmp/scan.json
  exit 1
fi
```

### CI/CD Pipeline

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Install DeployGuard
        run: |
          pip install deployguard
      
      - name: Scan for secrets
        run: |
          deployguard scan local . --severity high --output scan.json --format json
      
      - name: Upload report
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: scan.json
```

### Weekly Repository Audit

```bash
#!/bin/bash
# audit-repos.sh

REPOS=("org/repo1" "org/repo2" "org/repo3")

for repo in "${REPOS[@]}"; do
  echo "Scanning $repo..."
  deployguard scan repo $repo \
    --output "reports/${repo//\//_}.json" \
    --format json
done

# Generate combined stats
for report in reports/*.json; do
  deployguard report stats "$report"
done
```

---

## ⚙️ Configuration Options

Edit `~/.deployguard/config.json`:

```json
{
  "github_token": "ghp_***",
  "bitbucket_username": "user@example.com",
  "bitbucket_app_password": "***",
  "default_output_dir": "./deployguard_reports",
  "default_report_format": "json",
  "scan_git_history": false,
  "auto_cleanup": false,
  "max_file_size_mb": 10
}
```

---

## 🔧 Detected Secret Types

- **AWS Keys**: Access keys, secret keys, session tokens
- **GitHub Tokens**: Personal access tokens, OAuth tokens
- **API Keys**: Stripe, SendGrid, Twilio, etc.
- **Database Connections**: MongoDB, PostgreSQL, MySQL
- **Private Keys**: RSA, SSH, PGP keys
- **OAuth Secrets**: Client secrets, refresh tokens
- **Passwords**: Hardcoded passwords in various formats
- **JWT Tokens**: JSON Web Tokens
- **Generic Secrets**: High-entropy strings (detected via Shannon entropy)

---

## 📊 Report Formats

### JSON Format
```json
{
  "scan_id": "uuid",
  "started_at": "2026-02-03T18:30:00",
  "files_scanned": 45,
  "total_findings": 8,
  "findings": [
    {
      "secret_type": "AWS_ACCESS_KEY",
      "severity": "CRITICAL",
      "file_path": "config.py",
      "line_number": 15,
      "masked_value": "AKIA****************",
      "suggested_variable": "AWS_ACCESS_KEY_ID"
    }
  ]
}
```

### CSV Format
```csv
Secret Type,Severity,File,Line,Masked Value,Suggested Variable
AWS_ACCESS_KEY,CRITICAL,config.py,15,AKIA****************,AWS_ACCESS_KEY_ID
GITHUB_TOKEN,HIGH,deploy.sh,42,ghp_****************,GITHUB_TOKEN
```

### HTML Format
Pretty formatted HTML report with color-coded severity levels.

---

## ❓ Troubleshooting

### "GitHub authentication required"
```bash
deployguard auth configure --github-token YOUR_TOKEN
deployguard auth status  # Verify
```

### "Command not found: deployguard"
```bash
# Reinstall in development mode
pip install -e .

# Or check if venv is activated
source venv/bin/activate
```

### View Help
```bash
deployguard --help
deployguard scan --help
deployguard scan local --help
deployguard auth --help
deployguard report --help
```

---

## 🚧 What's Next?

Currently implemented:
- ✅ Full CLI interface
- ✅ Local directory scanning
- ✅ GitHub/BitBucket repository scanning
- ✅ Multiple report formats (JSON, CSV, Text, HTML)
- ✅ Credential management
- ✅ Severity filtering

Coming soon:
- 🚧 Git history scanning
- 🚧 Automatic secret cleanup/rewriting
- 🚧 Publishing to cleaned repositories
- 🚧 REST API for integration
- 🚧 Web dashboard

---

## 📚 More Information

- Full Documentation: [PROJECT_DOCUMENTATION.md](PROJECT_DOCUMENTATION.md)
- Usage Guide: [USAGE_GUIDE.md](USAGE_GUIDE.md)
- Development: [DEVELOPMENT_SUMMARY.md](DEVELOPMENT_SUMMARY.md)

---

**Version**: 0.1.0 (Alpha)  
**Status**: CLI Ready for Production Use!  
**Support**: GitHub Issues
