# 🛡️ DeployGuard - Usage Guide

## Current Status: Alpha (Programmatic Use Only)

The core scanning engine is **production-ready** but there's **no CLI interface yet**. Here's how to use it:

---

## 📋 Prerequisites

1. **GitHub Personal Access Token** (for GitHub scanning)
   - Go to https://github.com/settings/tokens
   - Generate new token (classic)
   - Required scopes: `repo`, `read:org`
   - Save token securely

2. **BitBucket App Password** (for BitBucket scanning)
   - Go to BitBucket Settings → App passwords
   - Create app password with `repository:read` permission

---

## 🚀 Quick Start

### Option 1: Scan Local Directory

```bash
cd /Users/salginci/Source/GITHUB/deployguard_repository_cleaner
source venv/bin/activate
python example_usage.py
# Select option 2
# Enter your directory path
```

### Option 2: Scan GitHub Repository

```bash
# Set your GitHub token
export GITHUB_TOKEN="ghp_your_token_here"

# Run the scanner
python example_usage.py
# Select option 1
# Enter repo (e.g., "torvalds/linux")
```

---

## 💻 Programmatic Usage

### Scan a Local Directory

```python
from deployguard.core.scanner import SecretScanner
from pathlib import Path

# Initialize scanner
scanner = SecretScanner()

# Scan directory
result = scanner.scan_directory("/path/to/your/project")

# Check results
print(f"Found {result.total_findings} secrets in {result.files_scanned} files")

for finding in result.findings:
    print(f"{finding.secret_type}: {finding.file_path}:{finding.line_number}")
    print(f"  Severity: {finding.severity.value}")
    print(f"  Masked: {finding.masked_value}")
```

### Scan GitHub Repository

```python
from deployguard.platforms.github_adapter import GitHubAdapter
from deployguard.core.scanner import SecretScanner
import tempfile
import os

# Authenticate
github = GitHubAdapter(github_token="ghp_xxx")

# Get repositories
repos = github.get_repositories(owner="your-org")

# Clone and scan
temp_dir = tempfile.mkdtemp()
os.system(f"git clone https://github.com/owner/repo {temp_dir}")

scanner = SecretScanner()
result = scanner.scan_directory(temp_dir)

print(f"Found {result.total_findings} secrets")
```

### Scan BitBucket Repository

```python
from deployguard.platforms.bitbucket_adapter import BitBucketAdapter

# Authenticate
bitbucket = BitBucketAdapter(
    username="your-email@example.com",
    app_password="your-app-password"
)

# Get repositories
repos = bitbucket.get_repositories(workspace="your-workspace")
```

---

## 📊 Understanding Results

### Severity Levels

- **CRITICAL**: Hardcoded passwords, private keys, production credentials
- **HIGH**: API keys, OAuth tokens, database connection strings
- **MEDIUM**: Generic secrets detected by entropy analysis
- **LOW**: Potential secrets that may be false positives

### Finding Object

```python
finding.secret_type          # Type of secret (e.g., "AWS_ACCESS_KEY")
finding.severity             # Severity enum
finding.file_path            # Relative path to file
finding.line_number          # Line where secret was found
finding.masked_value         # Partially masked secret value
finding.suggested_variable   # Environment variable name suggestion
finding.raw_value            # Full secret (use carefully!)
```

---

## 🎯 Common Use Cases

### 1. Pre-Commit Hook
```bash
# Scan staged files before commit
python -c "
from deployguard.core.scanner import SecretScanner
import subprocess

changed_files = subprocess.check_output(['git', 'diff', '--cached', '--name-only'])
scanner = SecretScanner()

for file in changed_files.decode().split('\n'):
    if file:
        result = scanner.scan_file(file)
        if result.total_findings > 0:
            print(f'ERROR: Secrets found in {file}')
            exit(1)
"
```

### 2. CI/CD Pipeline
```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Scan for secrets
        run: |
          pip install -r requirements.txt
          python example_usage.py
```

### 3. Periodic Audit
```python
# Schedule this to run weekly
from deployguard.platforms.github_adapter import GitHubAdapter
from deployguard.core.scanner import SecretScanner
import os

github = GitHubAdapter(os.getenv("GITHUB_TOKEN"))
repos = github.get_repositories(owner="your-org")

for repo in repos:
    # Clone, scan, report
    # Send alerts if secrets found
```

---

## 🔧 Configuration

### Custom Secret Patterns

Edit `config/secret_patterns.yaml`:

```yaml
patterns:
  - pattern: 'custom_token_[A-Za-z0-9]{32}'
    secret_type: CUSTOM_TOKEN
    severity: HIGH
    description: Custom application token
```

### Entropy Detection Settings

```yaml
entropy_detection:
  enabled: true
  min_entropy: 4.5
  min_length: 20
```

### File Filtering

```yaml
file_filtering:
  include_patterns:
    - "**/*.py"
    - "**/*.js"
    - "**/*.env*"
  exclude_patterns:
    - "**/node_modules/**"
    - "**/.git/**"
    - "**/venv/**"
```

---

## ⚠️ What's NOT Available Yet

❌ **CLI Interface** - No command-line tool yet  
❌ **Git History Scanning** - Only scans current files  
❌ **Automatic Cleanup** - No code rewriting yet  
❌ **Repository Publishing** - Can't push cleaned code yet  
❌ **REST API** - No web API yet  

---

## 🚧 Next Steps (For Development)

To make this production-ready with full CLI:

1. **Build CLI** (Click/Typer)
   ```bash
   deployguard auth --github-token xxx
   deployguard scan --repo owner/repo
   deployguard report --format json
   deployguard clean --repo owner/repo --publish
   ```

2. **Add Git History Scanning** (git-filter-repo)
3. **Implement Code Cleanup** (rewrite files with env vars)
4. **Build REST API** (FastAPI)
5. **Add Integration Tests**

---

## 📞 Support

- Documentation: `PROJECT_DOCUMENTATION.md`
- Development: `DEVELOPMENT_SUMMARY.md`
- Issues: Create GitHub issue
- Tests: `pytest tests/unit/ -v`

---

**Current Version**: 0.1.0 (Alpha)  
**Status**: Core engine ready, CLI in development
