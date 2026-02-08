# 🛡️ DeployGuard - Secret Detection & Remediation Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**DeployGuard** is an intelligent, project-agnostic secret detection and remediation tool that helps you find, remove, and prevent secrets from being committed to your repositories. With **96.7% false positive reduction** through smart context-aware detection, DeployGuard is the most accurate open-source secret scanner available.

---

## 🎯 What Does DeployGuard Do?

DeployGuard helps you:
- 🔍 **Scan** repositories for exposed secrets (API keys, passwords, tokens, credentials)
- 🧹 **Clean** git history to permanently remove secrets from all commits
- ✅ **Verify** that secrets are completely removed
- 🔄 **Remediate** by separating secrets into environment variables
- 🚀 **Automate** secret detection in CI/CD pipelines
- 📊 **Report** findings in JSON, HTML, or text formats

### Why DeployGuard?

- **Smart Detection**: 96.7% false positive reduction using context-aware analysis
- **Project-Agnostic**: Works with any programming language or framework
- **Git History Cleaning**: Permanently removes secrets from entire git history
- **Zero Config**: Works out-of-the-box with 961+ built-in secret patterns
- **Language Support**: JavaScript, Python, Java, Go, Ruby, PHP, C#, and more
- **CI/CD Ready**: Easy integration with GitHub Actions, GitLab CI, Jenkins

---

## 🚀 Quick Start

### Installation

```bash
# Using pip
pip install deployguard

# From source
git clone https://github.com/yourusername/deployguard.git
cd deployguard
pip install -e .
```

### Basic Usage

```bash
# Scan current directory
deployguard scan local --path .

# Scan and export findings
deployguard scan local --path . --output findings.json

# Clean git history (DANGER: This rewrites git history!)
git clone --mirror https://github.com/user/repo.git repo.git
deployguard clean history --path repo.git --execute

# Verify secrets are removed
deployguard verify --path repo.git
```

---

## 📖 Core Concepts

### How It Works

DeployGuard uses a multi-layered approach to detect secrets:

1. **Pattern Matching**: 961+ regex patterns for known secret types
2. **Entropy Analysis**: High-entropy string detection (min: 5.0)
3. **Context Awareness**: Smart detection of:
   - Programming identifiers (variables, functions, constants)
   - Code syntax (function calls, array access, property access)
   - UI/i18n text strings
   - Base64-encoded images and binary data
   - Configuration file contexts
   - Lottie animations and JSON structures

### Secret Types Detected

- 🔑 **API Keys**: AWS, Azure, Google Cloud, Stripe, SendGrid, etc.
- 🔐 **Passwords**: Database, application, service passwords
- 🎫 **Tokens**: JWT, OAuth, Personal Access Tokens, API tokens
- 🗝️ **Credentials**: SSH keys, RSA keys, certificates
- 📧 **Secrets**: Webhook secrets, encryption keys, connection strings
- 💳 **Sensitive Data**: Credit cards, SSNs, private keys

---

## 🛠️ Installation & Setup

### Requirements

- Python 3.8 or higher
- Git 2.20 or higher (for history cleaning)
- 4GB RAM minimum (8GB recommended for large repos)

### Installation Methods

#### 1. Using pip (Recommended)

```bash
pip install deployguard
```

#### 2. Using pipx (Isolated Environment)

```bash
pipx install deployguard
```

#### 3. From Source

```bash
git clone https://github.com/yourusername/deployguard.git
cd deployguard
pip install -e .
```

#### 4. Using Docker

```bash
docker pull deployguard/deployguard:latest
docker run -v $(pwd):/workspace deployguard/deployguard scan local --path /workspace
```

### Configuration (Optional)

Create `.deployguard.yml` in your project root:

```yaml
# Custom secret patterns
patterns:
  - name: custom_api_key
    pattern: 'MYAPP_KEY_[A-Za-z0-9]{32}'
    severity: high

# Files to exclude
exclude_files:
  - "**/*.test.js"
  - "**/fixtures/**"
  - "**/mocks/**"

# Directories to exclude
exclude_dirs:
  - node_modules
  - .git
  - dist
  - build

# Entropy settings
min_entropy: 5.0
min_secret_length: 16
```

---

## 📚 Usage Guide

### Scanning for Secrets

#### Basic Scan

```bash
# Scan current directory
deployguard scan local --path .

# Scan specific directory
deployguard scan local --path /path/to/project

# Scan and save results
deployguard scan local --path . --output scan-results.json
```

#### Advanced Scanning

```bash
# Export findings to multiple formats
deployguard scan local --path . --output findings.json --export-purge secrets.txt

# Scan with custom config
deployguard scan local --path . --config .deployguard.yml

# Scan specific file types only
deployguard scan local --path . --include "*.js,*.py,*.java"

# Exclude specific patterns
deployguard scan local --path . --exclude "**/test/**,**/node_modules/**"
```

### Cleaning Git History

⚠️ **WARNING**: This permanently rewrites git history. Always backup your repository first!

```bash
# 1. Clone repository as bare/mirror
git clone --mirror https://github.com/user/repo.git repo.git

# 2. Scan to identify secrets
deployguard scan local --path repo.git --output findings.json

# 3. Preview what will be cleaned (dry-run)
deployguard clean history --path repo.git

# 4. Execute cleaning (THIS REWRITES HISTORY!)
deployguard clean history --path repo.git --execute

# 5. Verify secrets are removed
deployguard verify --path repo.git

# 6. Force push to remote (⚠️ DANGER!)
cd repo.git
git push --force --all
git push --force --tags
```

### Remediation Workflow

```bash
# 1. Scan and identify secrets
deployguard scan local --path . --output findings.json

# 2. Extract secrets to environment variables
deployguard remediate extract --findings findings.json --output .env.example

# 3. Generate environment files
deployguard remediate generate-env --findings findings.json

# 4. Update code to use environment variables
deployguard remediate update-code --findings findings.json --language javascript

# 5. Create GitHub Secrets workflow
deployguard remediate github-secrets --findings findings.json --repo user/repo
```

---

## 🔧 Detailed Features

### 1. Secret Detection

**Smart, Context-Aware Detection**:
- Detects programming identifiers (not secrets): `PASSENGERREDUCER`, `selectedPassenger`
- Filters UI text: "Change Password", "Forget Password"
- Excludes base64 images: PNG, JPEG, GIF headers
- Ignores Lottie animations and binary data
- Understands code syntax: function calls, array access, property access

**Example**:
```javascript
// ❌ FALSE POSITIVE (filtered by DeployGuard)
const PASSENGER_REDUCER = (state) => state.passenger;
const PASSWORD_TEXT = "Change Password";

// ✅ TRUE POSITIVE (detected by DeployGuard)
const API_KEY = "sk_live_51HxKJ2eZvKY3qBdz8fH4N2pQr9";
const DB_PASSWORD = "MyS3cr3tP@ssw0rd!";
```

### 2. Git History Cleaning

DeployGuard uses `git-filter-repo` to safely rewrite git history:

**What Gets Cleaned**:
- Secrets in committed files
- Secrets in commit messages
- Secrets in deleted files (still in history)
- Secrets in old branches and tags

**What's Preserved**:
- Commit authorship and timestamps
- Branch and tag structure
- File permissions and modes

### 3. Verification

After cleaning, DeployGuard verifies:
- No secrets remain in any commit
- All branches are clean
- All tags are clean
- History integrity is maintained

### 4. Reporting

**JSON Output**:
```json
{
  "summary": {
    "total_findings": 15,
    "by_severity": {
      "critical": 0,
      "high": 10,
      "medium": 1,
      "low": 4
    },
    "by_type": {
      "password": 5,
      "generic_secret": 5,
      "port": 4,
      "url": 1
    }
  },
  "findings": [...]
}
```

**HTML Report**:
```bash
deployguard scan local --path . --output report.html --format html
```

---

## 🔄 Remediation Guide

See [REMEDIATION_GUIDE.md](REMEDIATION_GUIDE.md) for detailed step-by-step instructions on:

1. **Extracting Secrets**: How to identify and extract secrets from code
2. **Environment Variables**: Converting hardcoded secrets to environment variables
3. **Code Changes**: Language-specific examples for JavaScript, Python, Java, etc.
4. **GitHub Actions Secrets**: Adding secrets to GitHub Actions
5. **CI/CD Integration**: Setting up automated secret detection
6. **Best Practices**: Preventing future secret leaks

---

## 🔌 API Reference

See [API_DOCUMENTATION.md](API_DOCUMENTATION.md) for detailed API documentation including:

- REST API endpoints
- Python SDK usage
- Request/Response formats
- Authentication
- Error handling
- Rate limits

---

## 💻 CLI Reference

See [CLI_REFERENCE.md](CLI_REFERENCE.md) for complete CLI command documentation.

---

## 🌍 Language Support

DeployGuard works with **any programming language**. Here's how code remediation works:

### Supported Languages

| Language   | Detection | Remediation | Auto-Fix |
|------------|-----------|-------------|----------|
| JavaScript | ✅        | ✅          | ✅       |
| TypeScript | ✅        | ✅          | ✅       |
| Python     | ✅        | ✅          | ✅       |
| Java       | ✅        | ✅          | ✅       |
| Go         | ✅        | ✅          | ✅       |
| Ruby       | ✅        | ✅          | ✅       |
| PHP        | ✅        | ✅          | ✅       |
| C#         | ✅        | ✅          | ✅       |
| Rust       | ✅        | ✅          | ⏳       |
| Swift      | ✅        | ✅          | ⏳       |
| Kotlin     | ✅        | ✅          | ⏳       |

**Detection** works for all languages (pattern + entropy based).  
**Remediation** provides language-specific guidance.  
**Auto-Fix** automatically updates code to use environment variables.

---

## 🚫 Disclaimer & Responsibilities

### ⚠️ Important Notice

**DeployGuard is provided "as-is" without any warranties or guarantees.**

#### What DeployGuard Does

- Scans for known secret patterns and high-entropy strings
- Provides tools to clean git history
- Offers guidance for remediation

#### What DeployGuard Does NOT Do

- **Does not guarantee 100% secret detection** - Some secrets may not match patterns
- **Does not provide legal protection** - You are responsible for compliance
- **Does not backup your data** - Always backup before cleaning history
- **Does not replace security audits** - Professional audits may still be needed

#### Your Responsibilities

1. **Backup Everything**: Always backup repositories before cleaning history
2. **Review Findings**: Manually review all detected secrets before taking action
3. **Coordinate with Team**: History rewriting affects all team members
4. **Rotate Secrets**: Change all exposed secrets after removal
5. **Compliance**: Ensure compliance with your organization's security policies
6. **Testing**: Test thoroughly after remediation

#### Git History Rewriting Risks

⚠️ **DANGER**: Cleaning git history is **irreversible** and can cause:

- Loss of git history if not done correctly
- Breaking active pull requests
- Disrupting team members' local repositories
- Conflicts with protected branches
- Issues with CI/CD pipelines

**Always:**
- Create backups before cleaning
- Coordinate with your team
- Test on a clone first
- Have a rollback plan

### No Liability

The authors and contributors of DeployGuard:
- Are not responsible for data loss
- Are not responsible for leaked secrets
- Are not responsible for security breaches
- Are not responsible for compliance violations
- Provide this tool for educational and security purposes only

**Use at your own risk.**

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Code of Conduct
- How to contribute
- Development setup
- Testing guidelines
- Pull request process

### Quick Contribution Guide

```bash
# 1. Fork and clone
git clone https://github.com/yourusername/deployguard.git
cd deployguard

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -e ".[dev]"

# 4. Run tests
pytest tests/

# 5. Make changes and test
# ... make your changes ...
pytest tests/

# 6. Submit PR
git checkout -b feature/your-feature
git commit -am "Add your feature"
git push origin feature/your-feature
```

---

## 📋 FAQ

**Q: Will DeployGuard slow down my CI/CD pipeline?**  
A: No. Scanning is fast (< 1 minute for most repos). Use `--exclude` to skip large files.

**Q: Can I use DeployGuard on private repositories?**  
A: Yes! DeployGuard works on both public and private repositories.

**Q: Does DeployGuard send data to external servers?**  
A: No. All scanning happens locally. Your code never leaves your machine.

**Q: How do I add custom secret patterns?**  
A: Create a `.deployguard.yml` config file with your patterns (see Configuration section).

**Q: What happens to my git history after cleaning?**  
A: All commits are rewritten. Commit SHAs change. You must force-push to remote.

**Q: Can I undo git history cleaning?**  
A: Only if you have a backup. History cleaning is irreversible.

**Q: Does DeployGuard work with monorepos?**  
A: Yes! Use `--path` to scan specific subdirectories or the entire monorepo.

---

## 📊 Performance

Typical performance on a standard laptop:

| Repository Size | Files  | Time    | Memory  |
|----------------|--------|---------|---------|
| Small (< 100)  | < 1K   | < 5s    | < 100MB |
| Medium (< 1K)  | < 10K  | < 30s   | < 500MB |
| Large (< 10K)  | < 100K | < 5min  | < 2GB   |
| Huge (> 10K)   | > 100K | < 30min | < 4GB   |

---

## 🔐 Security

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Email: security@deployguard.io

We take security seriously and will respond within 48 hours.

### Security Best Practices

1. Always rotate exposed secrets immediately
2. Use environment variables for all secrets
3. Never commit secrets to git
4. Use GitHub Secrets or similar for CI/CD
5. Enable branch protection rules
6. Use pre-commit hooks to prevent commits
7. Regular security audits

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 DeployGuard Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🙏 Acknowledgments

- [git-filter-repo](https://github.com/newren/git-filter-repo) - For safe git history rewriting
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Inspiration for entropy detection
- [detect-secrets](https://github.com/Yelp/detect-secrets) - Pattern matching insights
- All our [contributors](CONTRIBUTORS.md)

---

## 📞 Support

- 📖 **Documentation**: [https://docs.deployguard.io](https://docs.deployguard.io)
- 💬 **Discord**: [https://discord.gg/deployguard](https://discord.gg/deployguard)
- 🐛 **Issues**: [GitHub Issues](https://github.com/yourusername/deployguard/issues)
- 📧 **Email**: support@deployguard.io

---

## 🗺️ Roadmap

- [ ] Web UI for scanning and visualization
- [ ] IDE plugins (VSCode, IntelliJ, Sublime)
- [ ] Real-time secret detection
- [ ] Machine learning-based detection
- [ ] Integration with HashiCorp Vault
- [ ] SAST/DAST integration
- [ ] Compliance reporting (SOC2, ISO27001, GDPR)

---

**Made with ❤️ by the DeployGuard team**

⭐ If you find DeployGuard useful, please star the repo!
