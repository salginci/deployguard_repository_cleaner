# 🔌 DeployGuard API Documentation

Complete API reference for integrating DeployGuard into your applications.

---

## Table of Contents

- [REST API](#rest-api)
  - [Authentication](#authentication)
  - [Endpoints](#endpoints)
  - [Error Handling](#error-handling)
- [Python SDK](#python-sdk)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Classes](#classes)
- [Webhooks](#webhooks)
- [Rate Limits](#rate-limits)
- [Examples](#examples)

---

## REST API

### Base URL

```
http://localhost:8000/api/v1
```

### Authentication

DeployGuard API uses API keys for authentication.

**Header:**
```
Authorization: Bearer YOUR_API_KEY
```

**Get API Key:**
```bash
deployguard auth login
deployguard auth create-key --name "my-app-key"
```

**Example:**
```bash
curl -H "Authorization: Bearer dg_xxxxxxxxxxxx" \
  http://localhost:8000/api/v1/scan
```

---

### Endpoints

## `POST /scan`

Scan a repository for secrets.

**Request:**
```json
{
  "repository": {
    "type": "local",
    "path": "/path/to/repo"
  },
  "options": {
    "severity": "high",
    "include": ["*.js", "*.py"],
    "exclude": ["**/test/**"],
    "max_file_size_mb": 10
  }
}
```

**Response:**
```json
{
  "scan_id": "scan_abc123",
  "status": "completed",
  "summary": {
    "total_findings": 15,
    "scan_time": 2.34,
    "files_scanned": 1234,
    "by_severity": {
      "critical": 0,
      "high": 10,
      "medium": 3,
      "low": 2
    }
  },
  "findings": [
    {
      "id": "finding_123",
      "type": "aws_access_key",
      "severity": "high",
      "file": "config/aws.py",
      "line": 12,
      "value": "AKIA****************",
      "pattern": "AWS Access Key",
      "entropy": 5.2
    }
  ]
}
```

**Status Codes:**
- `200 OK` - Scan completed successfully
- `202 Accepted` - Scan started (async)
- `400 Bad Request` - Invalid request
- `401 Unauthorized` - Invalid API key
- `429 Too Many Requests` - Rate limit exceeded

---

## `GET /scan/{scan_id}`

Get scan results by ID.

**Request:**
```bash
GET /api/v1/scan/scan_abc123
```

**Response:**
```json
{
  "scan_id": "scan_abc123",
  "status": "completed",
  "created_at": "2024-01-15T10:30:00Z",
  "completed_at": "2024-01-15T10:30:02Z",
  "summary": { ... },
  "findings": [ ... ]
}
```

**Status Codes:**
- `200 OK` - Scan found
- `404 Not Found` - Scan not found

---

## `POST /clean`

Clean secrets from git history.

⚠️ **WARNING**: This rewrites git history!

**Request:**
```json
{
  "repository": {
    "path": "/path/to/repo.git"
  },
  "findings": "scan_abc123",
  "options": {
    "replace_text": "***REMOVED***",
    "preserve_emails": true,
    "preserve_dates": true
  },
  "execute": false
}
```

**Response:**
```json
{
  "clean_id": "clean_xyz789",
  "status": "preview",
  "preview": {
    "commits_to_modify": 150,
    "files_to_modify": 12,
    "secrets_to_remove": 15
  },
  "warnings": [
    "This will rewrite git history",
    "All commit SHAs will change",
    "Force push required"
  ]
}
```

**Status Codes:**
- `200 OK` - Cleaning preview/completed
- `400 Bad Request` - Invalid request
- `500 Internal Server Error` - Cleaning failed

---

## `POST /verify`

Verify secrets have been removed.

**Request:**
```json
{
  "repository": {
    "path": "/path/to/repo.git"
  },
  "original_scan_id": "scan_abc123"
}
```

**Response:**
```json
{
  "verification_id": "verify_def456",
  "status": "clean",
  "secrets_found": 0,
  "original_secrets": 15,
  "removed": 15,
  "remaining": 0,
  "branches_verified": ["main", "develop"]
}
```

---

## `POST /remediate/extract`

Extract secrets to environment variables.

**Request:**
```json
{
  "scan_id": "scan_abc123",
  "format": "env",
  "prefix": "APP_"
}
```

**Response:**
```json
{
  "env_file": "# AWS Credentials\nAWS_ACCESS_KEY=AKIA...\nAWS_SECRET_KEY=...",
  "variables": [
    {
      "name": "APP_AWS_ACCESS_KEY",
      "description": "AWS Access Key from config/aws.py:12",
      "masked_value": "AKIA****************"
    }
  ]
}
```

---

## `GET /scans`

List all scans.

**Request:**
```bash
GET /api/v1/scans?limit=10&offset=0&status=completed
```

**Query Parameters:**
- `limit` - Number of results (default: 10, max: 100)
- `offset` - Pagination offset (default: 0)
- `status` - Filter by status: pending, running, completed, failed

**Response:**
```json
{
  "total": 25,
  "limit": 10,
  "offset": 0,
  "scans": [
    {
      "scan_id": "scan_abc123",
      "status": "completed",
      "created_at": "2024-01-15T10:30:00Z",
      "summary": { ... }
    }
  ]
}
```

---

### Error Handling

**Error Response Format:**
```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Path is required",
    "details": {
      "field": "repository.path",
      "reason": "missing_required_field"
    }
  }
}
```

**Error Codes:**

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_REQUEST` | 400 | Invalid request parameters |
| `UNAUTHORIZED` | 401 | Invalid or missing API key |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |
| `GIT_ERROR` | 500 | Git operation failed |
| `SCAN_FAILED` | 500 | Scanning failed |

---

## Python SDK

### Installation

```bash
pip install deployguard
```

### Usage

#### Basic Scanning

```python
from deployguard import DeployGuard

# Initialize
dg = DeployGuard(api_key="dg_xxxxxxxxxxxx")

# Scan local repository
results = dg.scan_local("/path/to/repo")

print(f"Found {results.total_findings} secrets")
for finding in results.findings:
    print(f"  - {finding.type} in {finding.file}:{finding.line}")
```

#### Advanced Scanning

```python
from deployguard import DeployGuard, ScanOptions

dg = DeployGuard(api_key="dg_xxxxxxxxxxxx")

# Configure scan options
options = ScanOptions(
    severity="high",
    include=["*.js", "*.py"],
    exclude=["**/test/**"],
    max_file_size_mb=10,
    threads=8
)

# Scan with options
results = dg.scan_local("/path/to/repo", options=options)

# Export findings
results.export_json("findings.json")
results.export_html("report.html")
```

#### Git History Cleaning

```python
from deployguard import DeployGuard

dg = DeployGuard()

# Scan first
scan_results = dg.scan_local("repo.git")

# Preview cleaning (dry-run)
clean_preview = dg.clean_history("repo.git", findings=scan_results, execute=False)
print(f"Will modify {clean_preview.commits_to_modify} commits")

# Execute cleaning (⚠️ REWRITES HISTORY!)
clean_results = dg.clean_history("repo.git", findings=scan_results, execute=True)
print(f"Cleaned {clean_results.secrets_removed} secrets")

# Verify
verification = dg.verify("repo.git", original_findings=scan_results)
print(f"Verification: {verification.status}")
```

#### Remediation

```python
from deployguard import DeployGuard

dg = DeployGuard()

# Scan
results = dg.scan_local(".")

# Extract secrets to .env file
env_vars = dg.remediate_extract(results, format="env", output=".env.example")
print(env_vars)

# Update code to use environment variables
updates = dg.remediate_update_code(results, language="javascript", dry_run=True)
for update in updates:
    print(f"Would update {update.file}:{update.line}")

# Generate GitHub secrets setup script
script = dg.remediate_github_secrets(results, repo="user/repo")
with open("setup-secrets.sh", "w") as f:
    f.write(script)
```

---

### Classes

#### `DeployGuard`

Main client class.

**Constructor:**
```python
DeployGuard(
    api_key: Optional[str] = None,
    base_url: str = "http://localhost:8000/api/v1",
    timeout: int = 30
)
```

**Methods:**

##### `scan_local(path, options=None)`

Scan a local repository.

**Parameters:**
- `path` (str): Path to repository
- `options` (ScanOptions, optional): Scan configuration

**Returns:** `ScanResults`

**Example:**
```python
results = dg.scan_local("/path/to/repo")
```

##### `scan_remote(url, branch="main", token=None, options=None)`

Scan a remote repository.

**Parameters:**
- `url` (str): Repository URL
- `branch` (str): Branch to scan
- `token` (str, optional): Authentication token
- `options` (ScanOptions, optional): Scan configuration

**Returns:** `ScanResults`

**Example:**
```python
results = dg.scan_remote("https://github.com/user/repo", branch="develop")
```

##### `clean_history(path, findings=None, purge_file=None, execute=False, **kwargs)`

Clean secrets from git history.

**Parameters:**
- `path` (str): Path to git repository
- `findings` (ScanResults, optional): Scan results
- `purge_file` (str, optional): File containing secrets to purge
- `execute` (bool): Execute cleaning (default: False for dry-run)
- `replace_text` (str): Replacement text (default: "***REMOVED***")
- `preserve_emails` (bool): Preserve commit emails (default: True)
- `preserve_dates` (bool): Preserve commit dates (default: True)

**Returns:** `CleanResults`

**Example:**
```python
results = dg.clean_history("repo.git", findings=scan_results, execute=True)
```

##### `verify(path, original_findings=None)`

Verify secrets have been removed.

**Parameters:**
- `path` (str): Path to git repository
- `original_findings` (ScanResults, optional): Original scan results

**Returns:** `VerificationResults`

**Example:**
```python
verification = dg.verify("repo.git", original_findings=scan_results)
```

##### `remediate_extract(findings, format="env", output=None, prefix="")`

Extract secrets to environment variables.

**Parameters:**
- `findings` (ScanResults): Scan results
- `format` (str): Output format: "env", "yaml", "json"
- `output` (str, optional): Output file path
- `prefix` (str): Variable name prefix

**Returns:** `str` (environment file content)

**Example:**
```python
env_content = dg.remediate_extract(results, format="env", output=".env.example")
```

##### `remediate_update_code(findings, language, dry_run=False, backup=True)`

Update code to use environment variables.

**Parameters:**
- `findings` (ScanResults): Scan results
- `language` (str): Programming language
- `dry_run` (bool): Preview changes only
- `backup` (bool): Create backup files

**Returns:** `List[CodeUpdate]`

**Example:**
```python
updates = dg.remediate_update_code(results, language="python", dry_run=True)
```

##### `remediate_github_secrets(findings, repo)`

Generate GitHub secrets setup script.

**Parameters:**
- `findings` (ScanResults): Scan results
- `repo` (str): GitHub repository (user/repo)

**Returns:** `str` (shell script)

**Example:**
```python
script = dg.remediate_github_secrets(results, repo="user/repo")
```

---

#### `ScanResults`

Scan results container.

**Properties:**
- `scan_id` (str): Unique scan identifier
- `status` (str): Scan status
- `total_findings` (int): Total number of findings
- `scan_time` (float): Scan duration in seconds
- `files_scanned` (int): Number of files scanned
- `summary` (dict): Summary statistics
- `findings` (List[Finding]): List of findings

**Methods:**

##### `export_json(file_path)`

Export findings to JSON file.

**Example:**
```python
results.export_json("findings.json")
```

##### `export_html(file_path)`

Export findings to HTML report.

**Example:**
```python
results.export_html("report.html")
```

##### `export_csv(file_path)`

Export findings to CSV file.

**Example:**
```python
results.export_csv("findings.csv")
```

##### `filter(severity=None, types=None)`

Filter findings by severity or type.

**Example:**
```python
high_severity = results.filter(severity="high")
aws_keys = results.filter(types=["aws_access_key"])
```

---

#### `Finding`

Individual secret finding.

**Properties:**
- `id` (str): Unique finding identifier
- `type` (str): Secret type
- `severity` (str): Severity level
- `file` (str): File path
- `line` (int): Line number
- `column` (int): Column number
- `value` (str): Masked secret value
- `pattern` (str): Pattern name
- `entropy` (float): Entropy score
- `context` (str): Code context

**Methods:**

##### `to_dict()`

Convert finding to dictionary.

**Example:**
```python
finding_dict = finding.to_dict()
```

---

#### `ScanOptions`

Scan configuration options.

**Properties:**
- `severity` (str): Minimum severity level
- `include` (List[str]): File patterns to include
- `exclude` (List[str]): File patterns to exclude
- `types` (List[str]): Secret types to scan
- `max_file_size_mb` (int): Maximum file size
- `threads` (int): Number of scanning threads
- `no_entropy` (bool): Disable entropy detection

**Example:**
```python
options = ScanOptions(
    severity="high",
    include=["*.js", "*.py"],
    exclude=["**/test/**"],
    threads=8
)
```

---

## Webhooks

DeployGuard can send webhooks for scan events.

### Configuration

```python
from deployguard import DeployGuard

dg = DeployGuard()
dg.configure_webhook(
    url="https://your-app.com/webhooks/deployguard",
    events=["scan.completed", "scan.failed"],
    secret="webhook_secret_key"
)
```

### Webhook Payload

```json
{
  "event": "scan.completed",
  "timestamp": "2024-01-15T10:30:02Z",
  "data": {
    "scan_id": "scan_abc123",
    "status": "completed",
    "summary": {
      "total_findings": 15,
      "by_severity": { ... }
    }
  },
  "signature": "sha256=..."
}
```

### Events

- `scan.started` - Scan started
- `scan.completed` - Scan completed successfully
- `scan.failed` - Scan failed
- `clean.completed` - History cleaning completed
- `verify.completed` - Verification completed

### Signature Verification

```python
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
```

---

## Rate Limits

**Limits:**
- 100 requests per minute per API key
- 1000 requests per hour per API key
- 10 concurrent scans per API key

**Headers:**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1610720400
```

**429 Response:**
```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Try again in 60 seconds.",
    "retry_after": 60
  }
}
```

---

## Examples

### Example 1: Simple Scan

```python
from deployguard import DeployGuard

dg = DeployGuard()
results = dg.scan_local(".")

if results.total_findings > 0:
    print(f"❌ Found {results.total_findings} secrets!")
    results.export_html("report.html")
else:
    print("✅ No secrets found")
```

### Example 2: Scan with Filters

```python
from deployguard import DeployGuard, ScanOptions

dg = DeployGuard()

options = ScanOptions(
    severity="high",
    include=["*.js", "*.py"],
    exclude=["**/test/**", "**/node_modules/**"],
    threads=8
)

results = dg.scan_local(".", options=options)

# Filter AWS-related secrets only
aws_secrets = results.filter(types=["aws_access_key", "aws_secret_key"])
print(f"Found {len(aws_secrets)} AWS secrets")
```

### Example 3: Full Remediation Workflow

```python
from deployguard import DeployGuard

dg = DeployGuard()

# 1. Scan
print("🔍 Scanning...")
results = dg.scan_local(".")

if results.total_findings == 0:
    print("✅ No secrets found")
    exit(0)

print(f"Found {results.total_findings} secrets")

# 2. Extract to .env
print("📝 Extracting secrets...")
env_content = dg.remediate_extract(results, output=".env.example")

# 3. Update code (dry-run)
print("🔄 Previewing code updates...")
updates = dg.remediate_update_code(results, language="python", dry_run=True)
for update in updates:
    print(f"  - {update.file}:{update.line}")

# 4. Generate GitHub secrets script
print("🔐 Generating GitHub secrets setup...")
script = dg.remediate_github_secrets(results, repo="user/repo")
with open("setup-secrets.sh", "w") as f:
    f.write(script)

print("✅ Remediation files generated:")
print("  - .env.example")
print("  - setup-secrets.sh")
```

### Example 4: CI/CD Integration

```python
import os
import sys
from deployguard import DeployGuard, ScanOptions

def main():
    dg = DeployGuard(api_key=os.getenv("DEPLOYGUARD_API_KEY"))
    
    options = ScanOptions(severity="high")
    results = dg.scan_local(".", options=options)
    
    if results.total_findings > 0:
        print(f"❌ SECURITY ALERT: Found {results.total_findings} secrets!")
        results.export_json("security-findings.json")
        
        # Fail CI build
        sys.exit(1)
    else:
        print("✅ Security scan passed")
        sys.exit(0)

if __name__ == "__main__":
    main()
```

### Example 5: Async Scanning (for large repos)

```python
import asyncio
from deployguard import AsyncDeployGuard

async def scan_multiple_repos():
    dg = AsyncDeployGuard()
    
    repos = [
        "/path/to/repo1",
        "/path/to/repo2",
        "/path/to/repo3"
    ]
    
    # Scan all repos concurrently
    tasks = [dg.scan_local(repo) for repo in repos]
    results = await asyncio.gather(*tasks)
    
    for i, result in enumerate(results):
        print(f"{repos[i]}: {result.total_findings} secrets found")

asyncio.run(scan_multiple_repos())
```

---

## API Versioning

Current version: `v1`

**Base URL:** `http://localhost:8000/api/v1`

**Version Header:**
```
X-API-Version: v1
```

---

## Support

- 📖 **Documentation**: [https://docs.deployguard.io/api](https://docs.deployguard.io/api)
- 🐛 **Issues**: [GitHub Issues](https://github.com/yourusername/deployguard/issues)
- 📧 **Email**: api-support@deployguard.io

---

**API Documentation v1.0** | Last updated: 2024-01-15
