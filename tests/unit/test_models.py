"""Unit tests for core models."""

import pytest
from datetime import datetime
from uuid import UUID

from deployguard.core.models import (
    Finding,
    Platform,
    Repository,
    ScanResult,
    ScanStatus,
    SecretType,
    Severity,
)


@pytest.mark.unit
class TestRepository:
    """Test Repository model."""

    def test_repository_creation(self):
        """Test creating a repository with minimal data."""
        repo = Repository(
            platform=Platform.GITHUB,
            owner="testuser",
            name="test-repo",
        )

        assert isinstance(repo.id, UUID)
        assert repo.platform == Platform.GITHUB
        assert repo.owner == "testuser"
        assert repo.name == "test-repo"
        assert repo.full_name == "testuser/test-repo"
        assert isinstance(repo.created_at, datetime)

    def test_repository_clone_url_github(self):
        """Test GitHub clone URL generation."""
        repo = Repository(
            platform=Platform.GITHUB,
            owner="testuser",
            name="test-repo",
        )

        assert repo.clone_url == "https://github.com/testuser/test-repo.git"

    def test_repository_clone_url_bitbucket(self):
        """Test BitBucket clone URL generation."""
        repo = Repository(
            platform=Platform.BITBUCKET,
            owner="testuser",
            name="test-repo",
        )

        assert repo.clone_url == "https://bitbucket.org/testuser/test-repo.git"

    def test_repository_with_custom_url(self):
        """Test repository with custom URL."""
        custom_url = "https://custom.git.server/repo.git"
        repo = Repository(
            platform=Platform.GITHUB,
            owner="testuser",
            name="test-repo",
            url=custom_url,
        )

        assert repo.clone_url == custom_url


@pytest.mark.unit
class TestFinding:
    """Test Finding model."""

    def test_finding_creation(self):
        """Test creating a finding."""
        finding = Finding(
            type=SecretType.AWS_ACCESS_KEY,
            severity=Severity.CRITICAL,
            file_path="config.py",
            line_number=10,
            exposed_value="AKIAFAKEKEY12345FAKE",
        )

        assert isinstance(finding.id, UUID)
        assert finding.type == SecretType.AWS_ACCESS_KEY
        assert finding.severity == Severity.CRITICAL
        assert finding.file_path == "config.py"
        assert finding.line_number == 10

    def test_finding_mask_value(self):
        """Test masking exposed values."""
        finding = Finding(
            type=SecretType.AWS_ACCESS_KEY,
            severity=Severity.CRITICAL,
            file_path="config.py",
            line_number=10,
            exposed_value="AKIAFAKEKEY12345FAKE",
        )

        masked = finding.mask_value(show_chars=4)
        assert masked.startswith("AKIA")
        assert masked.endswith("FAKE")
        assert "*" in masked
        assert len(masked) == len(finding.exposed_value)

    def test_finding_mask_short_value(self):
        """Test masking short values."""
        finding = Finding(
            type=SecretType.PASSWORD,
            severity=Severity.HIGH,
            file_path="config.py",
            line_number=10,
            exposed_value="short",
        )

        masked = finding.mask_value(show_chars=4)
        assert masked == "*****"


@pytest.mark.unit
class TestScanResult:
    """Test ScanResult model."""

    def test_scan_result_creation(self):
        """Test creating a scan result."""
        scan = ScanResult(
            status=ScanStatus.PENDING,
            branches_scanned=[],
            commits_scanned=0,
            files_scanned=0,
        )

        assert isinstance(scan.id, UUID)
        assert scan.status == ScanStatus.PENDING
        assert scan.branches_scanned == []
        assert scan.total_findings == 0

    def test_scan_result_findings_by_severity(self):
        """Test counting findings by severity."""
        scan = ScanResult(
            status=ScanStatus.COMPLETED,
            findings=[
                Finding(
                    type=SecretType.AWS_ACCESS_KEY,
                    severity=Severity.CRITICAL,
                    file_path="a.py",
                    line_number=1,
                    exposed_value="test1",
                ),
                Finding(
                    type=SecretType.API_KEY,
                    severity=Severity.HIGH,
                    file_path="b.py",
                    line_number=1,
                    exposed_value="test2",
                ),
                Finding(
                    type=SecretType.PASSWORD,
                    severity=Severity.HIGH,
                    file_path="c.py",
                    line_number=1,
                    exposed_value="test3",
                ),
            ],
        )

        severity_counts = scan.findings_by_severity
        assert severity_counts[Severity.CRITICAL] == 1
        assert severity_counts[Severity.HIGH] == 2
        assert severity_counts[Severity.MEDIUM] == 0

    def test_scan_result_excludes_false_positives(self):
        """Test that false positives are excluded from counts."""
        scan = ScanResult(
            status=ScanStatus.COMPLETED,
            findings=[
                Finding(
                    type=SecretType.AWS_ACCESS_KEY,
                    severity=Severity.CRITICAL,
                    file_path="a.py",
                    line_number=1,
                    exposed_value="test1",
                    false_positive=False,
                ),
                Finding(
                    type=SecretType.API_KEY,
                    severity=Severity.HIGH,
                    file_path="b.py",
                    line_number=1,
                    exposed_value="test2",
                    false_positive=True,
                ),
            ],
        )

        assert scan.total_findings == 1
        severity_counts = scan.findings_by_severity
        assert severity_counts[Severity.CRITICAL] == 1
        assert severity_counts[Severity.HIGH] == 0

    def test_scan_result_duration(self, sample_scan_result):
        """Test duration calculation."""
        scan = sample_scan_result
        scan.started_at = datetime(2024, 1, 1, 10, 0, 0)
        scan.completed_at = datetime(2024, 1, 1, 10, 5, 30)

        duration = scan.duration_seconds
        assert duration == 330.0  # 5 minutes 30 seconds
