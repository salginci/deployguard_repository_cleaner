"""Tests for the secret verifier module."""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from deployguard.core.models import Finding, SecretType, Severity
from deployguard.core.verifier import (
    SecretVerifier,
    VerificationResult,
    VerificationStatus,
    verify_secrets_sync,
)


@pytest.fixture
def sample_finding():
    """Create a sample finding for testing."""
    return Finding(
        type=SecretType.API_KEY,
        exposed_value="ghp_fakefakefakefakefakefakefakefakefake",
        file_path="test.py",
        line_number=10,
        context='token = "ghp_fakefakefakefakefakefakefakefakefake"',
        severity=Severity.HIGH,
    )


@pytest.fixture
def github_finding():
    """Create a GitHub token finding."""
    finding = MagicMock()
    finding.secret_type = MagicMock()
    finding.secret_type.value = "github_token"
    finding.value = "ghp_fakefakefakefakefakefakefakefakefake"
    finding.file_path = "test.py"
    finding.line_number = 10
    return finding


@pytest.fixture
def aws_finding():
    """Create an AWS access key finding."""
    finding = MagicMock()
    finding.secret_type = MagicMock()
    finding.secret_type.value = "aws_access_key"
    finding.value = "AKIAFAKEKEY12345FAKE"
    finding.file_path = "config.py"
    finding.line_number = 5
    return finding


@pytest.fixture
def stripe_finding():
    """Create a Stripe API key finding."""
    finding = MagicMock()
    finding.secret_type = MagicMock()
    finding.secret_type.value = "stripe_api_key"
    finding.value = "sk_test_fakefakefake1234567890fake"
    finding.file_path = "payment.py"
    finding.line_number = 15
    return finding


@pytest.fixture
def openai_finding():
    """Create an OpenAI API key finding."""
    finding = MagicMock()
    finding.secret_type = MagicMock()
    finding.secret_type.value = "openai_api_key"
    finding.value = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"
    finding.file_path = "ai.py"
    finding.line_number = 20
    return finding


class TestVerificationResult:
    """Tests for VerificationResult dataclass."""
    
    def test_creation(self, sample_finding):
        """Test creating a verification result."""
        result = VerificationResult(
            finding=sample_finding,
            status=VerificationStatus.VERIFIED_ACTIVE,
            message="Token is valid"
        )
        
        assert result.finding == sample_finding
        assert result.status == VerificationStatus.VERIFIED_ACTIVE
        assert result.message == "Token is valid"
        assert result.verified_at is not None
        assert isinstance(result.verified_at, datetime)
    
    def test_with_details(self, sample_finding):
        """Test creating a result with details."""
        result = VerificationResult(
            finding=sample_finding,
            status=VerificationStatus.VERIFIED_ACTIVE,
            message="Token is valid",
            details={"user": "testuser", "scopes": "repo,read:org"}
        )
        
        assert result.details == {"user": "testuser", "scopes": "repo,read:org"}


class TestVerificationStatus:
    """Tests for VerificationStatus enum."""
    
    def test_status_values(self):
        """Test all status values exist."""
        assert VerificationStatus.VERIFIED_ACTIVE.value == "verified_active"
        assert VerificationStatus.VERIFIED_INACTIVE.value == "verified_inactive"
        assert VerificationStatus.UNVERIFIED.value == "unverified"
        assert VerificationStatus.ERROR.value == "error"
        assert VerificationStatus.RATE_LIMITED.value == "rate_limited"


class TestSecretVerifier:
    """Tests for SecretVerifier class."""
    
    @pytest.mark.asyncio
    async def test_unsupported_secret_type(self):
        """Test verification of unsupported secret type."""
        finding = MagicMock()
        finding.secret_type = MagicMock()
        finding.secret_type.value = "unknown_type"
        finding.value = "some_secret"
        
        verifier = SecretVerifier()
        async with verifier:
            result = await verifier.verify_finding(finding)
        
        assert result.status == VerificationStatus.UNVERIFIED
        assert "not supported" in result.message.lower()
    
    @pytest.mark.asyncio
    async def test_aws_key_format_check(self, aws_finding):
        """Test AWS key verification (format check)."""
        verifier = SecretVerifier()
        verifier._session = MagicMock()  # Mock session
        
        result = await verifier.verify_finding(aws_finding)
        
        # AWS requires both access key and secret key
        assert result.status == VerificationStatus.UNVERIFIED
        assert "access key and secret key" in result.message.lower()
    
    @pytest.mark.asyncio
    async def test_github_token_verification_success(self, github_finding):
        """Test successful GitHub token verification."""
        verifier = SecretVerifier()
        
        # Mock the aiohttp response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"login": "testuser"})
        mock_response.headers = {"X-OAuth-Scopes": "repo,user"}
        
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response)))
        
        verifier._session = mock_session
        
        result = await verifier.verify_finding(github_finding)
        
        assert result.status == VerificationStatus.VERIFIED_ACTIVE
        assert "valid" in result.message.lower()
    
    @pytest.mark.asyncio
    async def test_github_token_verification_invalid(self, github_finding):
        """Test invalid GitHub token verification."""
        verifier = SecretVerifier()
        
        mock_response = AsyncMock()
        mock_response.status = 401
        
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response)))
        
        verifier._session = mock_session
        
        result = await verifier.verify_finding(github_finding)
        
        assert result.status == VerificationStatus.VERIFIED_INACTIVE
        assert "invalid" in result.message.lower() or "expired" in result.message.lower()
    
    @pytest.mark.asyncio
    async def test_stripe_verification_success(self, stripe_finding):
        """Test successful Stripe API key verification."""
        verifier = SecretVerifier()
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"livemode": True})
        
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response)))
        
        verifier._session = mock_session
        
        result = await verifier.verify_finding(stripe_finding)
        
        assert result.status == VerificationStatus.VERIFIED_ACTIVE
    
    @pytest.mark.asyncio
    async def test_openai_verification_rate_limited(self, openai_finding):
        """Test OpenAI rate limiting handling."""
        verifier = SecretVerifier()
        
        mock_response = AsyncMock()
        mock_response.status = 429
        
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response)))
        
        verifier._session = mock_session
        
        result = await verifier.verify_finding(openai_finding)
        
        assert result.status == VerificationStatus.RATE_LIMITED
    
    @pytest.mark.asyncio
    async def test_verification_timeout(self, github_finding):
        """Test verification timeout handling."""
        verifier = SecretVerifier(timeout=1)
        
        # Create a mock that raises TimeoutError when used as context manager
        async def raise_timeout(*args, **kwargs):
            raise asyncio.TimeoutError()
        
        mock_cm = MagicMock()
        mock_cm.__aenter__ = raise_timeout
        mock_cm.__aexit__ = AsyncMock()
        
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_cm)
        
        verifier._session = mock_session
        
        result = await verifier.verify_finding(github_finding)
        
        assert result.status == VerificationStatus.ERROR
        assert "timed out" in result.message.lower()
    
    @pytest.mark.asyncio
    async def test_verify_multiple_findings(self):
        """Test verifying multiple findings concurrently."""
        findings = []
        for i in range(3):
            finding = MagicMock()
            finding.secret_type = MagicMock()
            finding.secret_type.value = "unknown_type"
            finding.value = f"secret_{i}"
            findings.append(finding)
        
        verifier = SecretVerifier()
        
        # Mock session with context manager
        async def mock_context(*args, **kwargs):
            class MockCM:
                async def __aenter__(self):
                    return MagicMock()
                async def __aexit__(self, *args):
                    pass
            return MockCM()
        
        with patch('aiohttp.ClientSession') as mock_cls:
            mock_session = MagicMock()
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_cls.return_value.__aexit__ = AsyncMock()
            
            results = await verifier.verify_findings(findings)
        
        assert len(results) == 3
        for result in results:
            assert result.status == VerificationStatus.UNVERIFIED


class TestVerifySecretsSync:
    """Tests for the synchronous wrapper."""
    
    def test_sync_wrapper_with_empty_list(self):
        """Test sync wrapper with empty findings list."""
        results = verify_secrets_sync([])
        assert results == []
    
    def test_sync_wrapper_with_unsupported_type(self):
        """Test sync wrapper with unsupported secret type."""
        finding = MagicMock()
        finding.secret_type = MagicMock()
        finding.secret_type.value = "unsupported_type"
        finding.value = "test_secret"
        
        results = verify_secrets_sync([finding])
        
        assert len(results) == 1
        assert results[0].status == VerificationStatus.UNVERIFIED


class TestSlackVerification:
    """Tests for Slack token verification."""
    
    @pytest.mark.asyncio
    async def test_slack_webhook_format_valid(self):
        """Test Slack webhook URL format validation."""
        finding = MagicMock()
        finding.secret_type = MagicMock()
        finding.secret_type.value = "slack_webhook"
        # Using placeholder that won't trigger GitHub secret scanning
        finding.value = "https://hooks.example.com/services/TXXXXXXXX/BXXXXXXXX/xxxxxxxxxxxxxxxxxxxxxxxx"
        
        verifier = SecretVerifier()
        verifier._session = MagicMock()
        
        result = await verifier.verify_finding(finding)
        
        # Will be inactive since domain is not slack.com
        assert result.status == VerificationStatus.VERIFIED_INACTIVE
    
    @pytest.mark.asyncio
    async def test_slack_bot_token_success(self):
        """Test Slack bot token verification success."""
        finding = MagicMock()
        finding.secret_type = MagicMock()
        finding.secret_type.value = "slack_bot_token"
        finding.value = "xoxb-fake-fake-fakefakefakefakefakefakefake"
        
        verifier = SecretVerifier()
        
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(return_value={"ok": True, "team": "TestTeam", "user": "bot"})
        
        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response)))
        
        verifier._session = mock_session
        
        result = await verifier.verify_finding(finding)
        
        assert result.status == VerificationStatus.VERIFIED_ACTIVE
        assert "TestTeam" in result.message


class TestSentryDSNVerification:
    """Tests for Sentry DSN verification."""
    
    @pytest.mark.asyncio
    async def test_sentry_dsn_valid_format(self):
        """Test Sentry DSN format validation."""
        finding = MagicMock()
        finding.secret_type = MagicMock()
        finding.secret_type.value = "sentry_dsn"
        finding.value = "https://abc123@o123456.ingest.sentry.io/1234567"
        
        verifier = SecretVerifier()
        verifier._session = MagicMock()
        
        result = await verifier.verify_finding(finding)
        
        assert result.status == VerificationStatus.UNVERIFIED
        assert "format is valid" in result.message.lower()
    
    @pytest.mark.asyncio
    async def test_sentry_dsn_invalid_format(self):
        """Test invalid Sentry DSN format."""
        finding = MagicMock()
        finding.secret_type = MagicMock()
        finding.secret_type.value = "sentry_dsn"
        finding.value = "https://invalid-dsn"
        
        verifier = SecretVerifier()
        verifier._session = MagicMock()
        
        result = await verifier.verify_finding(finding)
        
        assert result.status == VerificationStatus.VERIFIED_INACTIVE


class TestMongoDBVerification:
    """Tests for MongoDB connection string verification."""
    
    @pytest.mark.asyncio
    async def test_mongodb_connection_valid_format(self):
        """Test MongoDB connection string format validation."""
        finding = MagicMock()
        finding.secret_type = MagicMock()
        finding.secret_type.value = "mongodb_connection"
        finding.value = "mongodb+srv://user:password@cluster.mongodb.net/mydb"
        
        verifier = SecretVerifier()
        verifier._session = MagicMock()
        
        result = await verifier.verify_finding(finding)
        
        assert result.status == VerificationStatus.UNVERIFIED
        assert "format is valid" in result.message.lower()


class TestDiscordVerification:
    """Tests for Discord verification."""
    
    @pytest.mark.asyncio
    async def test_discord_webhook_valid(self):
        """Test Discord webhook verification."""
        finding = MagicMock()
        finding.secret_type = MagicMock()
        finding.secret_type.value = "discord_webhook"
        finding.value = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz"
        
        verifier = SecretVerifier()
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"name": "Test Webhook"})
        
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response)))
        
        verifier._session = mock_session
        
        result = await verifier.verify_finding(finding)
        
        assert result.status == VerificationStatus.VERIFIED_ACTIVE
