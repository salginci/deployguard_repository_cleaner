# Contributing to DeployGuard

Thank you for your interest in contributing to DeployGuard! 🎉

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Pull Request Process](#pull-request-process)
- [Style Guide](#style-guide)
- [Testing](#testing)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)

---

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to:

- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy towards other contributors

---

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/deployguard_repository_cleaner.git
   cd deployguard_repository_cleaner
   ```
3. **Add upstream** remote:
   ```bash
   git remote add upstream https://github.com/salginci/deployguard_repository_cleaner.git
   ```

---

## Development Setup

### Prerequisites

- Python 3.10 or higher
- Git
- Virtual environment (recommended)

### Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Verify installation
deployguard --version
pytest --version
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=deployguard --cov-report=html

# Run specific test file
pytest tests/unit/test_scanner.py

# Run tests matching a pattern
pytest -k "test_scan"
```

---

## How to Contribute

### Types of Contributions

| Type | Description |
|------|-------------|
| 🐛 **Bug Fixes** | Fix issues reported in GitHub Issues |
| ✨ **Features** | Add new functionality |
| 📝 **Documentation** | Improve docs, examples, or README |
| 🧪 **Tests** | Add or improve test coverage |
| 🎨 **Refactoring** | Code quality improvements |
| 🔍 **Patterns** | Add new secret detection patterns |

### Adding Secret Detection Patterns

To add a new secret detection pattern:

1. Edit `config/secret_patterns.yaml`
2. Add your pattern following this format:
   ```yaml
   - name: "My Service API Key"
     pattern: 'MY_SERVICE_[A-Za-z0-9]{32}'
     secret_type: "api_key"
     severity: "high"
     description: "My Service API key detected"
     remediation: "Rotate the key at https://myservice.com/api-keys"
   ```
3. Add tests in `tests/unit/test_patterns.py`
4. Submit a PR with example (redacted) strings that match

---

## Pull Request Process

### Before Submitting

1. **Sync with upstream:**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run checks locally:**
   ```bash
   # Format code
   black deployguard tests
   isort deployguard tests
   
   # Lint
   flake8 deployguard tests
   
   # Type check
   mypy deployguard
   
   # Run tests
   pytest
   ```

3. **Update documentation** if needed

### PR Guidelines

- Use clear, descriptive titles
- Reference any related issues (e.g., "Fixes #123")
- Include tests for new functionality
- Keep PRs focused (one feature/fix per PR)
- Update CHANGELOG.md for user-facing changes

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Refactoring

## Testing
- [ ] Tests pass locally
- [ ] Added new tests
- [ ] Updated documentation

## Related Issues
Fixes #(issue number)
```

---

## Style Guide

### Python Code Style

- **Formatter:** Black (line length: 100)
- **Imports:** isort with Black profile
- **Docstrings:** Google style
- **Type hints:** Required for public APIs

### Example

```python
def scan_file(
    file_path: Path,
    patterns: list[SecretPattern],
    *,
    include_entropy: bool = True,
) -> list[Finding]:
    """Scan a file for secrets.

    Args:
        file_path: Path to the file to scan.
        patterns: List of patterns to match against.
        include_entropy: Whether to include entropy-based detection.

    Returns:
        List of findings detected in the file.

    Raises:
        ScanError: If the file cannot be read.
    """
    ...
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add Slack token verification
fix: handle Unicode characters in secret values
docs: update API integration guide
test: add tests for history cleaner
refactor: extract pattern matching to separate module
```

---

## Testing

### Test Structure

```
tests/
├── unit/           # Unit tests (fast, isolated)
├── integration/    # Integration tests (may use filesystem/network)
├── fixtures/       # Test data and mock files
└── conftest.py     # Shared fixtures
```

### Writing Tests

```python
import pytest
from deployguard.core.scanner import SecretScanner

class TestSecretScanner:
    """Tests for SecretScanner class."""

    def test_detects_aws_access_key(self, scanner: SecretScanner):
        """Should detect AWS access keys."""
        content = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        findings = scanner.scan_content(content, "config.py")
        
        assert len(findings) == 1
        assert findings[0].secret_type == "aws_access_key"

    def test_ignores_example_keys(self, scanner: SecretScanner):
        """Should ignore obvious example/placeholder keys."""
        content = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'  # AWS example key
        findings = scanner.scan_content(content, "README.md")
        
        assert len(findings) == 0
```

---

## Reporting Bugs

### Before Reporting

1. Check existing [GitHub Issues](https://github.com/salginci/deployguard_repository_cleaner/issues)
2. Try the latest version
3. Reproduce with minimal example

### Bug Report Template

```markdown
**Describe the bug**
Clear description of the issue

**To Reproduce**
1. Run command '...'
2. With file containing '...'
3. See error

**Expected behavior**
What you expected to happen

**Environment**
- OS: [e.g., macOS 14.0, Ubuntu 22.04]
- Python: [e.g., 3.11.5]
- DeployGuard version: [e.g., 0.1.6]

**Additional context**
Any other relevant information
```

---

## Feature Requests

We welcome feature requests! Please:

1. Check if the feature already exists
2. Search existing issues for similar requests
3. Open a new issue with:
   - Clear use case description
   - Why this would be valuable
   - Possible implementation ideas (optional)

---

## Questions?

- 💬 Open a [GitHub Discussion](https://github.com/salginci/deployguard_repository_cleaner/discussions)
- 📧 Email: [maintainer email]
- 🐛 [Report Issues](https://github.com/salginci/deployguard_repository_cleaner/issues)

---

Thank you for contributing to DeployGuard! 🛡️
