"""Unit tests for secret scanner."""

import pytest
from pathlib import Path

from deployguard.core.scanner import SecretScanner, SecretPattern
from deployguard.core.models import SecretType, Severity


@pytest.mark.unit
class TestSecretPattern:
    """Test SecretPattern class."""

    def test_pattern_creation(self):
        """Test creating a secret pattern."""
        pattern = SecretPattern(
            name="AWS Key",
            pattern="AKIA[A-Z0-9]{16}",
            secret_type="aws_access_key",
            severity="critical",
            description="AWS access key",
        )

        assert pattern.name == "AWS Key"
        assert pattern.secret_type == SecretType.AWS_ACCESS_KEY
        assert pattern.severity == Severity.CRITICAL

    def test_pattern_matching(self):
        """Test pattern regex matching."""
        pattern = SecretPattern(
            name="AWS Key",
            pattern="AKIA[A-Z0-9]{16}",
            secret_type="aws_access_key",
            severity="critical",
        )

        test_code = 'AWS_KEY = "AKIAFAKEKEY12345FAKE"'
        match = pattern.pattern.search(test_code)

        assert match is not None
        assert match.group(0) == "AKIAFAKEKEY12345FAKE"


@pytest.mark.unit
class TestSecretScanner:
    """Test SecretScanner class."""

    def test_scanner_initialization(self, patterns_config):
        """Test scanner initialization with config."""
        scanner = SecretScanner(patterns_file=patterns_config)

        assert len(scanner.patterns) > 0
        assert scanner.entropy_enabled is True
        assert scanner.min_entropy == 4.5

    def test_scan_file_with_aws_key(self, patterns_config):
        """Test scanning a file with AWS key."""
        scanner = SecretScanner(patterns_file=patterns_config)

        code = '''
import os

AWS_ACCESS_KEY = "AKIAFAKEKEY12345FAKE"
'''

        findings = scanner.scan_file("test.py", code)

        assert len(findings) > 0
        aws_finding = next(
            (f for f in findings if f.type == SecretType.AWS_ACCESS_KEY),
            None,
        )
        assert aws_finding is not None
        assert aws_finding.file_path == "test.py"
        assert aws_finding.severity == Severity.CRITICAL
        assert "AKIAFAKEKEY12345FAKE" in aws_finding.exposed_value

    def test_scan_file_with_github_token(self, patterns_config):
        """Test scanning a file with GitHub token."""
        scanner = SecretScanner(patterns_file=patterns_config)

        code = '''
const token = "ghp_fakefakefakefakefakefakefakefakefake";
'''

        findings = scanner.scan_file("test.js", code)

        assert len(findings) > 0
        github_finding = next(
            (f for f in findings if f.type == SecretType.GITHUB_TOKEN),
            None,
        )
        assert github_finding is not None

    def test_scan_file_no_secrets(self, patterns_config):
        """Test scanning a clean file."""
        scanner = SecretScanner(patterns_file=patterns_config)

        code = '''
import os

def hello():
    print("Hello, world!")
'''

        findings = scanner.scan_file("test.py", code)

        # Should have no findings or only low-severity findings
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0

    def test_scan_directory(self, patterns_config, sample_code_with_secrets):
        """Test scanning a directory."""
        scanner = SecretScanner(patterns_file=patterns_config)

        results = scanner.scan_directory(str(sample_code_with_secrets))

        # Should find secrets in multiple files
        assert len(results) > 0

        # Check for AWS keys in Python file
        python_findings = results.get("config.py")
        if python_findings:
            aws_findings = [
                f for f in python_findings if f.type == SecretType.AWS_ACCESS_KEY
            ]
            assert len(aws_findings) > 0

    def test_file_exclusion(self, patterns_config, temp_test_dir):
        """Test file exclusion patterns."""
        scanner = SecretScanner(patterns_file=patterns_config)

        # Create files in node_modules (should be excluded)
        node_modules = temp_test_dir / "node_modules"
        node_modules.mkdir()
        (node_modules / "package.js").write_text('const key = "AKIAFAKEKEY12345FAKE";')

        # Create normal file (should be included)
        (temp_test_dir / "app.js").write_text('const key = "AKIAFAKEKEY12345FAKE";')

        results = scanner.scan_directory(str(temp_test_dir))

        # Should only find secrets in app.js, not in node_modules
        assert "app.js" in results
        assert "node_modules/package.js" not in results

    def test_entropy_detection(self, patterns_config):
        """Test high-entropy string detection."""
        scanner = SecretScanner(patterns_file=patterns_config)

        # High entropy string (likely a secret)
        code = '''
SECRET = "aB3xK9mP2qR5tW8yZ1nL4cD7fG6hJ0sV"
'''

        findings = scanner.scan_file("test.py", code)

        # Should detect high entropy
        entropy_findings = [f for f in findings if "entropy" in f.description.lower()]
        assert len(entropy_findings) > 0

    def test_calculate_entropy(self, patterns_config):
        """Test entropy calculation."""
        scanner = SecretScanner(patterns_file=patterns_config)

        # Low entropy (repeated chars)
        low_entropy = scanner._calculate_entropy("aaaaaaaaaa")
        assert low_entropy < 1.0

        # High entropy (random chars)
        high_entropy = scanner._calculate_entropy("aB3xK9mP2qR5tW8yZ")
        assert high_entropy > 4.0

    def test_variable_name_generation(self, patterns_config):
        """Test generating unique variable names."""
        scanner = SecretScanner(patterns_file=patterns_config)

        # First AWS key should get base name
        var1 = scanner.generate_variable_name(SecretType.AWS_ACCESS_KEY, set())
        assert var1 == "AWS_ACCESS_KEY_ID"

        # Second AWS key should get numbered suffix
        var2 = scanner.generate_variable_name(SecretType.AWS_ACCESS_KEY, {var1})
        assert var2 == "AWS_ACCESS_KEY_ID_1"

        # Third AWS key
        var3 = scanner.generate_variable_name(
            SecretType.AWS_ACCESS_KEY, {var1, var2}
        )
        assert var3 == "AWS_ACCESS_KEY_ID_2"

    def test_context_extraction(self, patterns_config):
        """Test extracting context around findings."""
        scanner = SecretScanner(patterns_config)

        lines = [
            "import os",
            "",
            "# AWS Configuration",
            'AWS_KEY = "AKIATEST12345678"',
            "",
            "def main():",
            '    print("Hello")',
        ]

        context = scanner._extract_context(lines, 4, context_size=2)

        assert "# AWS Configuration" in context
        assert "AWS_KEY" in context
        assert ">>>" in context  # Highlight marker
        assert "def main():" in context
