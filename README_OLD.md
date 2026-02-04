# 🛡️ DeployGuard Repository Cleaner

<p align="center">
  <strong>Automatically detect, remove, and manage exposed secrets in your Git repositories</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#api">API</a> •
  <a href="#documentation">Documentation</a>
</p>

---

## 🚀 Features

- **🔍 Deep Scanning**: Scan all branches and complete Git history for exposed secrets
- **🔐 Multi-Platform**: Support for GitHub and BitBucket (GitLab coming soon)
- **🤖 Smart Detection**: Detect API keys, credentials, tokens, private keys, and more
- **✨ Auto-Remediation**: Automatically replace secrets with environment variables
- **📊 Interactive Reports**: Review findings with conflict-free variable name generation
- **🚀 One-Click Publishing**: Push cleaned code to new repositories
- **💻 Dual Interface**: Use as CLI tool or integrate via REST API
- **🌐 Open Source**: Self-hostable and fully transparent

---

## 📋 Quick Start

### CLI Usage

```bash
# Install
pip install deployguard

# Authenticate
deployguard auth login github

# Scan a repository
deployguard scan start --repo "owner/repo-name" --platform github

# Review and clean
deployguard report review <scan-id>
deployguard clean apply <scan-id>

# Publish to clean repository
deployguard publish create --source-scan <scan-id> --target-repo "owner/cleaned-repo"
```

### API Usage

```bash
# Start API server
docker-compose up -d

# Or run directly
uvicorn deployguard.api.app:app --reload
```

**API Example**:
```python
import requests

# Start a scan
response = requests.post("http://localhost:8000/api/scans", json={
    "platform": "github",
    "repository": "owner/repo-name"
})
scan_id = response.json()["scan_id"]

# Check status
status = requests.get(f"http://localhost:8000/api/scans/{scan_id}/status")
```

---

## 🎯 Use Cases

### For Developers
- Audit repositories before open-sourcing
- Clean up legacy codebases with hardcoded credentials
- Migrate from old repos to secure ones

### For Security Teams
- Automated security scanning in CI/CD pipelines
- Compliance auditing and reporting
- Incident response for leaked credentials

### For Enterprises
- Integrate into admin panels for self-service secret cleanup
- Enforce security policies across organizations
- Batch processing of multiple repositories

---

## 📥 Installation

### Option 1: Install from PyPI (Coming Soon)

```bash
pip install deployguard
```

### Option 2: Install from Source

```bash
git clone https://github.com/yourusername/deployguard_repository_cleaner.git
cd deployguard_repository_cleaner
pip install -e .
```

### Option 3: Docker

```bash
docker pull deployguard/deployguard:latest
docker run -it deployguard/deployguard deployguard --help
```

### Option 4: API Server (Self-Hosted)

```bash
git clone https://github.com/yourusername/deployguard_repository_cleaner.git
cd deployguard_repository_cleaner
docker-compose up -d
```

Access API at: `http://localhost:8000`
API Docs at: `http://localhost:8000/docs`

---

## 💻 Usage

### CLI Commands

#### Authentication
```bash
# GitHub Personal Access Token
deployguard auth login github

# BitBucket OAuth
deployguard auth login bitbucket

# Check authentication status
deployguard auth status
```

#### Scanning
```bash
# Basic scan
deployguard scan start --repo "owner/repo" --platform github

# Scan with options
deployguard scan start \
  --repo "owner/repo" \
  --platform github \
  --include-history \
  --branch-filter "main,develop"

# List all scans
deployguard scan list

# View scan results
deployguard scan results <scan-id>
```

#### Reporting
```bash
# Generate interactive report
deployguard report generate <scan-id> --format interactive

# Export to JSON/PDF
deployguard report export <scan-id> --output report.pdf
```

#### Cleanup
```bash
# Preview changes (dry run)
deployguard clean preview <scan-id>

# Apply cleanup
deployguard clean apply <scan-id> --confirm
```

#### Publishing
```bash
# Create new repository with cleaned code
deployguard publish create \
  --source-scan <scan-id> \
  --target-platform github \
  --target-repo "owner/cleaned-repo" \
  --create-repo

# Upload secrets to target platform
deployguard publish secrets \
  --scan-id <scan-id> \
  --target-repo "owner/cleaned-repo"
```

---

## 🔌 API Reference

### Authentication Endpoints

```http
POST /api/auth/github/token
POST /api/auth/bitbucket/oauth
GET  /api/auth/status
```

### Scan Endpoints

```http
POST   /api/scans                    # Start scan
GET    /api/scans/{scan_id}          # Get scan details
GET    /api/scans/{scan_id}/status   # Check status
GET    /api/scans/{scan_id}/report   # Get report
```

### Cleanup Endpoints

```http
POST /api/scans/{scan_id}/clean      # Apply cleanup
GET  /api/scans/{scan_id}/clean/preview
```

### Publish Endpoints

```http
POST /api/publish                    # Publish to target repo
GET  /api/publish/{job_id}/status
```

**Full API Documentation**: See [API_REFERENCE.md](docs/API_REFERENCE.md) or visit `/docs` endpoint.

---

## 🔧 Configuration

### Secret Detection Patterns

Customize detection patterns in `config/secret_patterns.yaml`:

```yaml
patterns:
  - name: "Custom API Key"
    pattern: "MYAPP_[A-Z0-9]{32}"
    severity: "high"
    description: "Custom application API key"
```

### Environment Variables

```bash
# API Configuration
DEPLOYGUARD_API_HOST=0.0.0.0
DEPLOYGUARD_API_PORT=8000
DATABASE_URL=postgresql://user:pass@localhost/deployguard
REDIS_URL=redis://localhost:6379/0

# Security
SECRET_KEY=your-secret-key
ENCRYPTION_KEY=your-encryption-key

# Platform Credentials
GITHUB_CLIENT_ID=your-github-app-id
GITHUB_CLIENT_SECRET=your-github-app-secret
```

---

## 📚 Documentation

- **[Project Documentation](PROJECT_DOCUMENTATION.md)** - Comprehensive technical documentation
- **[CLI Guide](docs/CLI_GUIDE.md)** - Detailed CLI usage examples
- **[API Reference](docs/API_REFERENCE.md)** - Complete API documentation
- **[Integration Guide](docs/INTEGRATION_GUIDE.md)** - Integrate into your applications
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Self-hosting and cloud deployment

---

## 🏗️ Architecture

**Technology Stack**:
- **Language**: Python 3.10+
- **CLI Framework**: Click/Typer
- **API Framework**: FastAPI
- **Git Operations**: GitPython
- **Secret Detection**: detect-secrets + custom patterns
- **Database**: PostgreSQL/SQLite
- **Cache**: Redis (optional)

**Architecture Pattern**: Hexagonal/Clean Architecture
- Core business logic independent of interfaces
- Pluggable platform adapters
- Shared service layer for CLI and API

---

## 🤝 Integration Examples

### Integrate into Admin Panel

```javascript
// Frontend (React example)
async function scanRepository(repoName) {
  const response = await fetch('http://api.deployguard.local/api/scans', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${userToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      platform: 'github',
      repository: repoName
    })
  });
  
  const { scan_id } = await response.json();
  
  // Poll for completion
  const result = await pollScanStatus(scan_id);
  return result;
}
```

### GitHub Actions Integration

```yaml
name: Secret Scan
on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Scan for secrets
        run: |
          pip install deployguard
          deployguard scan start --repo ${{ github.repository }} --platform github
```

---

## 🧪 Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/yourusername/deployguard_repository_cleaner.git
cd deployguard_repository_cleaner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run API server in dev mode
uvicorn deployguard.api.app:app --reload
```

### Running Tests

```bash
# Unit tests
pytest tests/unit

# Integration tests
pytest tests/integration

# Coverage report
pytest --cov=deployguard --cov-report=html
```

---

## 🛣️ Roadmap

### Version 1.0 (Current)
- [x] GitHub and BitBucket support
- [x] CLI interface
- [x] REST API
- [x] Basic secret detection
- [x] Git history rewriting
- [x] Report generation

### Version 1.1 (Next)
- [ ] GitLab support
- [ ] Enhanced ML-based detection
- [ ] Web UI
- [ ] Scheduled scanning
- [ ] Team collaboration features

### Version 2.0 (Future)
- [ ] Azure DevOps support
- [ ] CI/CD platform plugins
- [ ] Advanced compliance reporting
- [ ] Multi-repository batch processing
- [ ] Custom detection rules marketplace

---

## 🐛 Known Issues & Limitations

- Large repositories (>10GB) may require significant disk space
- Git history rewriting requires force push (destructive operation)
- Platform rate limits may slow down large batch operations
- Some proprietary secret formats may not be detected

---

## 🔒 Security

### Reporting Security Issues

**Do not** open public issues for security vulnerabilities. Email: security@deployguard.io

### Security Best Practices

1. **Never commit the generated `.env.secure` file**
2. **Always review reports before applying cleanup**
3. **Backup original repositories before cleanup**
4. **Rotate exposed secrets immediately**
5. **Use encrypted token storage**

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details

---

## 🙏 Acknowledgments

- [detect-secrets](https://github.com/Yelp/detect-secrets) - Secret detection patterns
- [GitPython](https://github.com/gitpython-developers/GitPython) - Git operations
- [FastAPI](https://fastapi.tiangolo.com/) - API framework
- [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/) - Git history cleaning

---

## 📞 Support

- **Documentation**: https://docs.deployguard.io
- **Issues**: [GitHub Issues](https://github.com/yourusername/deployguard_repository_cleaner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/deployguard_repository_cleaner/discussions)
- **Email**: support@deployguard.io

---

<p align="center">
  Made with ❤️ by the DeployGuard Team
</p>

<p align="center">
  <a href="https://github.com/yourusername/deployguard_repository_cleaner/stargazers">⭐ Star us on GitHub</a> •
  <a href="https://twitter.com/deployguard">🐦 Follow on Twitter</a>
</p>
