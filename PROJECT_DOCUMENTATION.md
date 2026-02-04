# DeployGuard Repository Cleaner - Project Documentation

## 📋 Executive Summary

**DeployGuard Repository Cleaner** is an open-source security tool that automatically detects, removes, and manages exposed secrets and sensitive credentials in Git repositories. It supports both standalone CLI usage and REST API integration for enterprise admin panels.

### Key Features
- 🔍 Deep repository scanning (all branches + git history)
- 🔐 Multi-platform support (GitHub, BitBucket)
- 🤖 Automatic secret detection and remediation
- 📊 Interactive reporting with conflict-free variable generation
- 🚀 Automated publishing to clean repositories
- 💻 Dual interface: CLI + REST API
- 🌐 Open-source and self-hostable

---

## 🏗️ Architecture Overview

### Technology Stack

**Core Language**: Python 3.10+

**Key Libraries**:
- **FastAPI**: REST API framework
- **Click/Typer**: CLI framework
- **GitPython**: Git operations and history analysis
- **PyGithub**: GitHub API integration
- **atlassian-python-api**: BitBucket API integration
- **detect-secrets**: Secret pattern detection
- **Jinja2**: Report generation
- **SQLite/PostgreSQL**: Session and state management
- **Redis** (optional): Background task queue

**Architecture Pattern**: Hexagonal/Clean Architecture
- Core business logic independent of interfaces
- Pluggable adapters for different Git platforms
- Shared service layer for CLI and API

---

## 📁 Project Structure

```
deployguard_repository_cleaner/
├── README.md
├── LICENSE
├── PROJECT_DOCUMENTATION.md
├── requirements.txt
├── setup.py
├── docker-compose.yml
├── .env.example
│
├── deployguard/
│   ├── __init__.py
│   ├── core/                      # Core business logic
│   │   ├── __init__.py
│   │   ├── models.py              # Data models (Repository, Secret, ScanResult)
│   │   ├── scanner.py             # Secret detection engine
│   │   ├── cleaner.py             # Code modification and cleanup
│   │   ├── variable_generator.py  # Unique variable name generation
│   │   └── git_operations.py     # Git history rewriting
│   │
│   ├── platforms/                 # Platform adapters
│   │   ├── __init__.py
│   │   ├── base.py               # Base platform interface
│   │   ├── github_adapter.py     # GitHub implementation
│   │   └── bitbucket_adapter.py  # BitBucket implementation
│   │
│   ├── services/                  # Business services
│   │   ├── __init__.py
│   │   ├── auth_service.py       # OAuth/token management
│   │   ├── repo_service.py       # Repository operations
│   │   ├── scan_service.py       # Scanning orchestration
│   │   ├── report_service.py     # Report generation
│   │   └── publish_service.py    # Publishing to target repos
│   │
│   ├── cli/                       # CLI interface
│   │   ├── __init__.py
│   │   ├── main.py               # CLI entry point
│   │   ├── commands/
│   │   │   ├── auth.py           # Authentication commands
│   │   │   ├── scan.py           # Scanning commands
│   │   │   ├── clean.py          # Cleaning commands
│   │   │   └── publish.py        # Publishing commands
│   │   └── ui.py                 # Interactive UI components
│   │
│   ├── api/                       # REST API interface
│   │   ├── __init__.py
│   │   ├── app.py                # FastAPI application
│   │   ├── routes/
│   │   │   ├── auth.py           # /api/auth endpoints
│   │   │   ├── repositories.py   # /api/repositories endpoints
│   │   │   ├── scans.py          # /api/scans endpoints
│   │   │   └── jobs.py           # /api/jobs endpoints (background tasks)
│   │   ├── schemas.py            # Pydantic models
│   │   └── middleware.py         # Auth, CORS, etc.
│   │
│   ├── storage/                   # Data persistence
│   │   ├── __init__.py
│   │   ├── database.py           # Database connection
│   │   ├── repositories.py       # Data access layer
│   │   └── models.py             # ORM models
│   │
│   └── utils/
│       ├── __init__.py
│       ├── crypto.py             # Encryption utilities
│       ├── logger.py             # Logging configuration
│       └── validators.py         # Input validation
│
├── config/
│   ├── secret_patterns.yaml      # Secret detection patterns
│   ├── logging.yaml              # Logging configuration
│   └── api_config.yaml           # API configuration
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
│
├── docs/
│   ├── CLI_GUIDE.md
│   ├── API_REFERENCE.md
│   ├── INTEGRATION_GUIDE.md
│   └── DEPLOYMENT.md
│
└── scripts/
    ├── setup_dev.sh
    └── generate_patterns.py
```

---

## 🔄 Workflow & Phases

### Phase 1: Authentication & Repository Selection

#### CLI Flow
```bash
# Authenticate with platform
deployguard auth login github
deployguard auth login bitbucket

# List repositories with search/filter
deployguard repos list --platform github --search "backend"
deployguard repos list --platform bitbucket --filter "team:engineering"
```

#### API Flow
```http
POST /api/auth/github/token
POST /api/auth/bitbucket/oauth

GET /api/repositories?platform=github&search=backend&page=1&limit=50
```

**Technical Details**:
- **GitHub**: Personal Access Token (PAT) or OAuth App
- **BitBucket**: OAuth 2.0 with App Password fallback
- Store encrypted tokens in local database
- Support for organization/workspace filtering
- Pagination for large repository lists (100s-1000s)

---

### Phase 2: Clone & Scan

#### CLI Flow
```bash
# Clone and scan repository (all branches)
deployguard scan start --repo "owner/repo-name" --platform github

# Monitor scan progress
deployguard scan status <scan-id>

# View preliminary results
deployguard scan results <scan-id>
```

#### API Flow
```http
POST /api/scans
{
  "platform": "github",
  "repository": "owner/repo-name",
  "scan_options": {
    "include_history": true,
    "branch_filter": "*",
    "max_depth": 1000
  }
}

GET /api/scans/{scan_id}/status
GET /api/scans/{scan_id}/results
```

**Technical Implementation**:

1. **Repository Cloning**
   - Clone to temporary directory (`/tmp/deployguard/<scan-id>`)
   - Fetch all branches and tags
   - Use shallow clone with gradual deepening for large repos

2. **Secret Detection Engine**
   - **Pattern-based detection**:
     - API keys (AWS, Azure, GCP, etc.)
     - Database credentials (connection strings)
     - Private keys (RSA, SSH, PGP)
     - JWT tokens
     - OAuth secrets
     - Generic patterns (PASSWORD=, API_KEY=)
   
   - **Entropy analysis**: High-entropy strings detection
   - **Contextual analysis**: Variable names suggesting secrets
   - **Git history scanning**: Use `git log -p` to scan all commits
   - **Multi-branch scanning**: Scan each branch independently

3. **Performance Optimization**
   - Parallel branch scanning
   - Commit chunking for large histories
   - Binary file exclusion
   - Vendor directory skipping

**Secret Detection Patterns** (config/secret_patterns.yaml):
```yaml
patterns:
  - name: "AWS Access Key"
    pattern: "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
    severity: "critical"
    
  - name: "GitHub Token"
    pattern: "ghp_[a-zA-Z0-9]{36}"
    severity: "critical"
    
  - name: "Database Connection String"
    pattern: "(mongodb|postgres|mysql|mariadb)://[^\\s]+"
    severity: "high"
    
  - name: "Private Key"
    pattern: "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    severity: "critical"
```

---

### Phase 3: Report Generation

#### CLI Flow
```bash
# Generate detailed report
deployguard report generate <scan-id> --format interactive

# Review findings
deployguard report review <scan-id>
```

#### API Flow
```http
GET /api/scans/{scan_id}/report

POST /api/scans/{scan_id}/review
{
  "findings": [
    {"id": "f-001", "action": "replace", "approved": true},
    {"id": "f-002", "action": "ignore", "reason": "false positive"}
  ]
}
```

**Report Structure**:
```json
{
  "scan_id": "scan-abc123",
  "repository": "owner/repo-name",
  "platform": "github",
  "scanned_at": "2026-02-03T10:30:00Z",
  "summary": {
    "total_secrets": 47,
    "critical": 12,
    "high": 18,
    "medium": 17,
    "branches_scanned": 15,
    "commits_scanned": 1250
  },
  "findings": [
    {
      "id": "f-001",
      "type": "AWS Access Key",
      "severity": "critical",
      "file": "src/config/aws.js",
      "line": 15,
      "branch": "main",
      "commit": "a1b2c3d",
      "exposed_value": "AKIA****************XYZW",
      "suggested_variable": "AWS_ACCESS_KEY_ID",
      "first_seen": "2024-05-12T08:22:00Z",
      "last_seen": "2026-01-15T14:30:00Z",
      "occurrences": 3
    }
  ],
  "variable_mapping": {
    "AKIA****************XYZW": "AWS_ACCESS_KEY_ID",
    "mongodb://user:pass@host": "MONGODB_CONNECTION_STRING"
  }
}
```

**Variable Name Generation**:
- Parse existing environment variable names in repo
- Generate semantic names based on secret type
- Ensure uniqueness with suffix numbering (_1, _2, etc.)
- Follow naming conventions (UPPER_SNAKE_CASE)
- Conflict detection against existing vars

**Interactive Review**:
- CLI: Terminal UI with keyboard navigation
- API: Return findings for UI display
- Allow marking false positives
- Batch approval/rejection
- Add custom variable names

---

### Phase 4: Secret Removal & Replacement

#### CLI Flow
```bash
# Apply approved changes
deployguard clean apply <scan-id> --confirm

# Preview changes (dry-run)
deployguard clean preview <scan-id>
```

#### API Flow
```http
POST /api/scans/{scan_id}/clean
{
  "dry_run": false,
  "generate_env_file": true,
  "create_backup": true
}

GET /api/scans/{scan_id}/clean/status
```

**Technical Implementation**:

1. **Code Modification**
   - Replace secrets with variable references
   - Maintain code syntax and formatting
   - Language-aware replacement:
     - Python: `os.getenv('VAR_NAME')`
     - JavaScript: `process.env.VAR_NAME`
     - Java: `System.getenv("VAR_NAME")`
     - Go: `os.Getenv("VAR_NAME")`

2. **Git History Rewriting**
   - Use `git filter-repo` or `BFG Repo-Cleaner`
   - Rewrite all commits containing secrets
   - Preserve commit metadata (author, date)
   - Update all branch refs
   - **WARNING**: This rewrites history (force push required)

3. **Environment File Generation**
   ```bash
   # Generated .env.template
   AWS_ACCESS_KEY_ID=your_aws_access_key_here
   AWS_SECRET_ACCESS_KEY=your_aws_secret_key_here
   MONGODB_CONNECTION_STRING=your_mongodb_connection_string
   ```

   ```bash
   # Generated .env.secure (encrypted actual values)
   AWS_ACCESS_KEY_ID=AKIA***ENCRYPTED***
   ```

4. **Backup Creation**
   - Create backup branch: `backup/pre-cleanup-<timestamp>`
   - Store original secrets in encrypted vault
   - Generate restoration script

---

### Phase 5: Publish & Deploy

#### CLI Flow
```bash
# Publish to new repository
deployguard publish create \
  --source-scan <scan-id> \
  --target-platform github \
  --target-repo "owner/cleaned-repo" \
  --create-repo

# Upload environment variables to platform
deployguard publish secrets \
  --scan-id <scan-id> \
  --target-repo "owner/cleaned-repo" \
  --platform github
```

#### API Flow
```http
POST /api/publish
{
  "scan_id": "scan-abc123",
  "target": {
    "platform": "github",
    "repository": "owner/cleaned-repo",
    "create_if_missing": true,
    "visibility": "private"
  },
  "secrets_config": {
    "upload_to_platform": true,
    "secret_type": "actions_secrets",  # GitHub Actions
    "environment": "production"
  }
}

GET /api/publish/{job_id}/status
```

**Technical Implementation**:

1. **Repository Creation**
   - Create new repository via platform API
   - Set visibility (private/public)
   - Initialize with README explaining the cleanup

2. **Code Publishing**
   - Push cleaned code to target repository
   - Push all cleaned branches
   - Create tags for versioning
   - Set default branch

3. **Secret Management**
   - **GitHub**: Upload to GitHub Actions Secrets or Dependabot Secrets
   - **BitBucket**: Upload to Repository Variables or Pipelines Variables
   - Encrypt secrets using platform's encryption
   - Set environment scopes (production, staging, etc.)

4. **Documentation Generation**
   - Generate SECURITY.md with cleanup details
   - Create MIGRATION.md with setup instructions
   - Update README with environment variable requirements

---

## 🔌 API Endpoints Reference

### Authentication Endpoints

```
POST   /api/auth/github/token          # Authenticate with GitHub PAT
POST   /api/auth/bitbucket/oauth       # OAuth flow for BitBucket
DELETE /api/auth/{platform}             # Logout/revoke token
GET    /api/auth/status                 # Check authentication status
```

### Repository Endpoints

```
GET    /api/repositories                # List repositories
GET    /api/repositories/{id}           # Get repository details
POST   /api/repositories/search         # Advanced search
```

### Scan Endpoints

```
POST   /api/scans                       # Start new scan
GET    /api/scans                       # List scans
GET    /api/scans/{scan_id}             # Get scan details
GET    /api/scans/{scan_id}/status      # Get scan status
GET    /api/scans/{scan_id}/results     # Get scan results
DELETE /api/scans/{scan_id}             # Cancel/delete scan
```

### Report Endpoints

```
GET    /api/scans/{scan_id}/report      # Get detailed report
POST   /api/scans/{scan_id}/review      # Submit review/approvals
GET    /api/scans/{scan_id}/export      # Export report (PDF/JSON)
```

### Cleanup Endpoints

```
POST   /api/scans/{scan_id}/clean       # Apply cleanup
GET    /api/scans/{scan_id}/clean/status # Get cleanup status
GET    /api/scans/{scan_id}/clean/preview # Preview changes
```

### Publish Endpoints

```
POST   /api/publish                     # Publish to target repo
GET    /api/publish/{job_id}/status     # Get publish status
POST   /api/publish/{job_id}/secrets    # Upload secrets to platform
```

### Webhook Endpoints (for async notifications)

```
POST   /api/webhooks/configure          # Set webhook URL
POST   /webhooks/events                 # Receive platform webhooks
```

---

## 💻 CLI Commands Reference

### Authentication

```bash
deployguard auth login <platform>        # Interactive login
deployguard auth logout <platform>       # Logout
deployguard auth status                  # Show auth status
```

### Repository Management

```bash
deployguard repos list --platform <platform> [--search <query>]
deployguard repos info <owner/repo> --platform <platform>
```

### Scanning

```bash
deployguard scan start --repo <owner/repo> --platform <platform> [options]
deployguard scan list                    # List all scans
deployguard scan status <scan-id>        # Check scan status
deployguard scan cancel <scan-id>        # Cancel running scan
deployguard scan results <scan-id>       # View results
```

### Reporting

```bash
deployguard report generate <scan-id> [--format json|interactive|html]
deployguard report review <scan-id>      # Interactive review
deployguard report export <scan-id> --output report.pdf
```

### Cleanup

```bash
deployguard clean preview <scan-id>      # Dry run
deployguard clean apply <scan-id>        # Apply changes
```

### Publishing

```bash
deployguard publish create --source-scan <scan-id> --target-repo <repo> [options]
deployguard publish secrets --scan-id <scan-id> --target-repo <repo>
```

---

## 🚀 Deployment Options

### 1. Standalone CLI (Open Source Users)

```bash
# Install via pip
pip install deployguard

# Or install from source
git clone https://github.com/yourusername/deployguard_repository_cleaner
cd deployguard_repository_cleaner
pip install -e .
```

### 2. Self-Hosted API Server

```bash
# Using Docker Compose
docker-compose up -d

# Or manual installation
pip install deployguard[api]
uvicorn deployguard.api.app:app --host 0.0.0.0 --port 8000
```

**Docker Compose Setup**:
```yaml
version: '3.8'
services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/deployguard
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis
  
  db:
    image: postgres:15
    volumes:
      - pgdata:/var/lib/postgresql/data
    environment:
      - POSTGRES_PASSWORD=changeme
  
  redis:
    image: redis:7-alpine
  
  worker:
    build: .
    command: celery -A deployguard.api.worker worker
    depends_on:
      - redis
      - db

volumes:
  pgdata:
```

### 3. Cloud Deployment

- **AWS**: ECS/Fargate with RDS and ElastiCache
- **Google Cloud**: Cloud Run with Cloud SQL
- **Azure**: Container Apps with Cosmos DB
- **Heroku**: Direct deployment with add-ons

---

## 🔐 Security Considerations

1. **Token Storage**
   - Encrypt platform tokens at rest (AES-256)
   - Never log tokens or secrets
   - Support token rotation

2. **Temporary Files**
   - Clone repos to encrypted temp directories
   - Automatic cleanup after processing
   - Secure deletion (shred/overwrite)

3. **API Security**
   - JWT authentication for API
   - Rate limiting
   - CORS configuration
   - Input validation and sanitization

4. **Secret Handling**
   - Generated .env files excluded from Git
   - Encrypted backup of original secrets
   - Secure transmission to target platforms

---

## 📊 Database Schema

```sql
-- Users (for API mode)
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    created_at TIMESTAMP
);

-- Platform Tokens
CREATE TABLE platform_tokens (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    platform VARCHAR(50),
    encrypted_token TEXT,
    expires_at TIMESTAMP,
    created_at TIMESTAMP
);

-- Scans
CREATE TABLE scans (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    platform VARCHAR(50),
    repository VARCHAR(500),
    status VARCHAR(50),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    metadata JSONB
);

-- Findings
CREATE TABLE findings (
    id UUID PRIMARY KEY,
    scan_id UUID REFERENCES scans(id),
    type VARCHAR(100),
    severity VARCHAR(20),
    file_path TEXT,
    line_number INTEGER,
    branch VARCHAR(255),
    commit_hash VARCHAR(40),
    exposed_value_hash VARCHAR(64),
    suggested_variable VARCHAR(255),
    status VARCHAR(50),
    reviewed_at TIMESTAMP
);

-- Cleanup Jobs
CREATE TABLE cleanup_jobs (
    id UUID PRIMARY KEY,
    scan_id UUID REFERENCES scans(id),
    status VARCHAR(50),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    changes_applied INTEGER,
    metadata JSONB
);

-- Publish Jobs
CREATE TABLE publish_jobs (
    id UUID PRIMARY KEY,
    scan_id UUID REFERENCES scans(id),
    target_platform VARCHAR(50),
    target_repository VARCHAR(500),
    status VARCHAR(50),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    metadata JSONB
);
```

---

## 🧪 Testing Strategy

1. **Unit Tests**
   - Secret pattern detection
   - Variable name generation
   - Git operations
   - Platform adapters

2. **Integration Tests**
   - End-to-end CLI workflows
   - API endpoint testing
   - Database operations
   - Platform API mocking

3. **Test Fixtures**
   - Sample repositories with known secrets
   - Mock API responses from GitHub/BitBucket
   - Simulated Git histories

---

## 📈 Future Enhancements

### Phase 6 (Future)
- **Additional Platforms**: GitLab, Azure DevOps, Gitea
- **CI/CD Integration**: GitHub Actions, BitBucket Pipelines plugins
- **Scheduled Scanning**: Periodic repository audits
- **Team Features**: Multi-user workflows, approval chains
- **Advanced Detection**: ML-based secret detection
- **Compliance Reports**: SOC2, GDPR compliance reporting
- **Slack/Email Notifications**: Alert on secret detection
- **Web UI**: Full-featured web application

---

## 🤝 Integration Guide (for Your Admin Panel)

### Example Integration Flow

```python
# In your admin panel backend
import requests

# 1. User initiates scan from your UI
response = requests.post(
    "http://deployguard-api:8000/api/scans",
    headers={"Authorization": f"Bearer {user_token}"},
    json={
        "platform": "github",
        "repository": "owner/repo-name",
        "scan_options": {"include_history": True}
    }
)
scan_id = response.json()["scan_id"]

# 2. Poll for scan completion
status = requests.get(
    f"http://deployguard-api:8000/api/scans/{scan_id}/status"
)

# 3. Display report in your UI
report = requests.get(
    f"http://deployguard-api:8000/api/scans/{scan_id}/report"
)

# 4. User reviews and approves in your UI, then trigger cleanup
requests.post(
    f"http://deployguard-api:8000/api/scans/{scan_id}/clean",
    json={"dry_run": False}
)

# 5. Publish to clean repo
requests.post(
    "http://deployguard-api:8000/api/publish",
    json={
        "scan_id": scan_id,
        "target": {
            "platform": "github",
            "repository": "owner/cleaned-repo"
        }
    }
)
```

---

## 📦 Deliverables

### Phase 1: Core Engine (Weeks 1-3)
- [ ] Project setup and structure
- [ ] GitHub/BitBucket authentication
- [ ] Repository cloning and management
- [ ] Secret detection engine
- [ ] Basic CLI commands

### Phase 2: Reporting & Cleanup (Weeks 4-5)
- [ ] Report generation
- [ ] Variable name generation
- [ ] Git history rewriting
- [ ] Environment file generation
- [ ] CLI interactive review

### Phase 3: Publishing (Week 6)
- [ ] Repository publishing
- [ ] Secret upload to platforms
- [ ] Documentation generation

### Phase 4: API Development (Weeks 7-8)
- [ ] FastAPI application
- [ ] All API endpoints
- [ ] Background job processing
- [ ] Database integration
- [ ] API authentication

### Phase 5: Testing & Documentation (Week 9)
- [ ] Unit and integration tests
- [ ] API documentation (OpenAPI/Swagger)
- [ ] CLI user guide
- [ ] Integration guide
- [ ] Deployment documentation

### Phase 6: Release (Week 10)
- [ ] Docker packaging
- [ ] PyPI publishing
- [ ] GitHub release
- [ ] Example integrations
- [ ] Video tutorials

---

## 📄 License

**Recommended**: MIT License (for open source)

---

## 🎯 Success Criteria

1. ✅ Successfully scan repos with 1000+ commits
2. ✅ Detect 99%+ of common secret types
3. ✅ Generate conflict-free variable names
4. ✅ Complete cleanup in <5 minutes for typical repos
5. ✅ API response time <200ms for most endpoints
6. ✅ Easy integration into existing admin panels
7. ✅ Comprehensive documentation and examples

---

## 📞 Support & Community

- **Documentation**: https://deployguard.readthedocs.io
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Slack**: #deployguard channel

---

**Last Updated**: February 3, 2026
**Version**: 1.0.0-draft
