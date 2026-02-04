"""Test fixtures and utilities."""

import pytest
from pathlib import Path
from uuid import uuid4

from deployguard.core.models import (
    Finding,
    Platform,
    Repository,
    ScanResult,
    ScanStatus,
    SecretType,
    Severity,
)


@pytest.fixture
def sample_repository():
    """Create a sample repository for testing."""
    return Repository(
        id=uuid4(),
        platform=Platform.GITHUB,
        owner="testuser",
        name="test-repo",
        full_name="testuser/test-repo",
        url="https://github.com/testuser/test-repo.git",
        default_branch="main",
        is_private=True,
    )


@pytest.fixture
def sample_finding():
    """Create a sample finding for testing."""
    return Finding(
        id=uuid4(),
        scan_id=uuid4(),
        type=SecretType.AWS_ACCESS_KEY,
        severity=Severity.CRITICAL,
        file_path="src/config.py",
        line_number=15,
        column_start=10,
        column_end=40,
        branch="main",
        commit_hash="abc123",
        exposed_value="AKIAFAKEKEY12345FAKE",
        exposed_value_hash="hash123",
        suggested_variable="AWS_ACCESS_KEY_ID",
        description="AWS Access Key detected",
    )


@pytest.fixture
def sample_scan_result(sample_repository, sample_finding):
    """Create a sample scan result for testing."""
    return ScanResult(
        id=uuid4(),
        repository_id=sample_repository.id,
        status=ScanStatus.COMPLETED,
        branches_scanned=["main", "develop"],
        commits_scanned=100,
        files_scanned=50,
        findings=[sample_finding],
    )


@pytest.fixture
def temp_test_dir(tmp_path):
    """Create a temporary directory for testing."""
    test_dir = tmp_path / "test_repo"
    test_dir.mkdir()
    return test_dir


@pytest.fixture
def sample_code_with_secrets(temp_test_dir):
    """Create sample code files with secrets for testing."""
    # Python file with AWS key
    python_file = temp_test_dir / "config.py"
    python_file.write_text("""
import os

# AWS Credentials
AWS_ACCESS_KEY = "AKIAFAKEKEY12345FAKE"
AWS_SECRET_KEY = "fakesecretkey1234567890fakefakefakefake"

# Database
DB_PASSWORD = "test_password_for_testing_123"
""")

    # JavaScript file with API key
    js_file = temp_test_dir / "app.js"
    js_file.write_text("""
const config = {
    apiKey: "sk_test_fakefakefakefakefake",
    githubToken: "ghp_fakefakefakefakefakefakefakefakefake",
};
""")

    return temp_test_dir


@pytest.fixture
def patterns_config(tmp_path):
    """Create a test patterns config file."""
    config_file = tmp_path / "test_patterns.yaml"
    config_file.write_text("""
patterns:
  - name: "AWS Access Key"
    pattern: "AKIA[A-Z0-9]{16}"
    secret_type: "aws_access_key"
    severity: "critical"
    description: "AWS Access Key detected"

  - name: "GitHub Token"
    pattern: "ghp_[a-zA-Z0-9]{36}"
    secret_type: "github_token"
    severity: "critical"
    description: "GitHub token detected"

  - name: "Generic API Key"
    pattern: "sk_live_[a-zA-Z0-9]{20,}"
    secret_type: "api_key"
    severity: "high"
    description: "API key detected"

file_patterns:
  include:
    - "**/*.py"
    - "**/*.js"
  exclude:
    - "**/node_modules/**"

entropy:
  enabled: true
  min_entropy: 4.5
  min_length: 20
""")
    return str(config_file)
