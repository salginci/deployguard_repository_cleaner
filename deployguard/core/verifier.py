"""Secret verification module for testing if detected secrets are active."""

import asyncio
import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import aiohttp

from deployguard.core.models import Finding


class VerificationStatus(str, Enum):
    """Status of secret verification."""
    
    VERIFIED_ACTIVE = "verified_active"  # Secret is valid and active
    VERIFIED_INACTIVE = "verified_inactive"  # Secret is invalid/revoked
    UNVERIFIED = "unverified"  # Could not verify (unsupported or error)
    ERROR = "error"  # Verification failed due to error
    RATE_LIMITED = "rate_limited"  # Hit rate limit during verification


@dataclass
class VerificationResult:
    """Result of secret verification."""
    
    finding: Finding
    status: VerificationStatus
    message: str
    details: Optional[Dict[str, Any]] = None
    verified_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.verified_at is None:
            self.verified_at = datetime.now()


class SecretVerifier:
    """
    Verifies if detected secrets are active by making API calls.
    
    Supports verification for:
    - AWS Access Keys
    - GitHub Tokens (PAT, OAuth, App)
    - GitLab Tokens
    - Slack Tokens
    - Stripe API Keys
    - Twilio API Keys
    - SendGrid API Keys
    - OpenAI API Keys
    - And more...
    """
    
    def __init__(self, timeout: int = 10, max_concurrent: int = 5):
        """
        Initialize the verifier.
        
        Args:
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent verification requests
        """
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        self._session = aiohttp.ClientSession(timeout=self.timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            await self._session.close()
    
    async def verify_findings(self, findings: List[Finding]) -> List[VerificationResult]:
        """
        Verify multiple findings concurrently.
        
        Args:
            findings: List of findings to verify
            
        Returns:
            List of verification results
        """
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            self._session = session
            tasks = [self._verify_with_semaphore(finding) for finding in findings]
            return await asyncio.gather(*tasks)
    
    async def _verify_with_semaphore(self, finding: Finding) -> VerificationResult:
        """Verify a finding with semaphore to limit concurrency."""
        async with self.semaphore:
            return await self.verify_finding(finding)
    
    async def verify_finding(self, finding: Finding) -> VerificationResult:
        """
        Verify a single finding.
        
        Args:
            finding: The finding to verify
            
        Returns:
            Verification result
        """
        secret_type = str(finding.secret_type.value) if hasattr(finding.secret_type, 'value') else str(finding.secret_type)
        secret_value = finding.value
        
        # Route to appropriate verifier based on secret type
        verifiers = {
            # AWS
            "aws_access_key": self._verify_aws_key,
            "aws_secret_key": self._verify_aws_key,
            
            # GitHub
            "github_token": self._verify_github_token,
            "github_pat": self._verify_github_token,
            "github_fine_grained_pat": self._verify_github_token,
            "github_oauth": self._verify_github_token,
            "github_app_token": self._verify_github_app_token,
            
            # GitLab
            "gitlab_token": self._verify_gitlab_token,
            "gitlab_pat": self._verify_gitlab_token,
            "gitlab_pipeline_token": self._verify_gitlab_token,
            
            # Slack
            "slack_bot_token": self._verify_slack_token,
            "slack_user_token": self._verify_slack_token,
            "slack_webhook": self._verify_slack_webhook,
            
            # Stripe
            "stripe_api_key": self._verify_stripe_key,
            "stripe": self._verify_stripe_key,
            "stripe_restricted": self._verify_stripe_key,
            
            # Twilio
            "twilio_api_key": self._verify_twilio_key,
            "twilio": self._verify_twilio_key,
            
            # SendGrid
            "sendgrid_api_key": self._verify_sendgrid_key,
            "sendgrid": self._verify_sendgrid_key,
            
            # OpenAI
            "openai_api_key": self._verify_openai_key,
            "openai": self._verify_openai_key,
            
            # Anthropic
            "anthropic_api_key": self._verify_anthropic_key,
            "anthropic": self._verify_anthropic_key,
            
            # HuggingFace
            "huggingface_token": self._verify_huggingface_token,
            "huggingface": self._verify_huggingface_token,
            
            # Mailchimp
            "mailchimp_api_key": self._verify_mailchimp_key,
            "mailchimp": self._verify_mailchimp_key,
            
            # Mailgun
            "mailgun_api_key": self._verify_mailgun_key,
            "mailgun": self._verify_mailgun_key,
            
            # Datadog
            "datadog_api_key": self._verify_datadog_key,
            "datadog": self._verify_datadog_key,
            
            # New Relic
            "newrelic_api_key": self._verify_newrelic_key,
            "newrelic": self._verify_newrelic_key,
            
            # Heroku
            "heroku_api_key": self._verify_heroku_key,
            "heroku": self._verify_heroku_key,
            
            # DigitalOcean
            "digitalocean_pat": self._verify_digitalocean_token,
            "digitalocean": self._verify_digitalocean_token,
            
            # NPM
            "npm_token": self._verify_npm_token,
            "npm": self._verify_npm_token,
            
            # PyPI
            "pypi_token": self._verify_pypi_token,
            "pypi": self._verify_pypi_token,
            
            # Discord
            "discord_webhook": self._verify_discord_webhook,
            "discord_bot_token": self._verify_discord_bot_token,
            
            # Shopify
            "shopify_token": self._verify_shopify_token,
            "shopify": self._verify_shopify_token,
            
            # Notion
            "notion": self._verify_notion_token,
            
            # Airtable
            "airtable": self._verify_airtable_key,
            
            # Asana
            "asana": self._verify_asana_token,
            
            # Linear
            "linear": self._verify_linear_token,
            
            # Sentry
            "sentry_dsn": self._verify_sentry_dsn,
            "sentry": self._verify_sentry_dsn,
            
            # Vault
            "vault_token": self._verify_vault_token,
            
            # Doppler
            "doppler_token": self._verify_doppler_token,
            
            # Supabase
            "supabase": self._verify_supabase_key,
            
            # PlanetScale
            "planetscale_password": self._verify_planetscale,
            
            # Vercel
            "vercel": self._verify_vercel_token,
            
            # Netlify
            "netlify_token": self._verify_netlify_token,
            
            # Fly.io
            "flyio_token": self._verify_flyio_token,
            
            # Cloudflare
            "cloudflare": self._verify_cloudflare_token,
            
            # Firebase
            "firebase": self._verify_firebase_key,
            
            # MongoDB
            "mongodb_connection": self._verify_mongodb_connection,
        }
        
        verifier = verifiers.get(secret_type)
        
        if verifier:
            try:
                return await verifier(finding, secret_value)
            except asyncio.TimeoutError:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message="Verification timed out"
                )
            except Exception as e:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Verification error: {str(e)}"
                )
        
        return VerificationResult(
            finding=finding,
            status=VerificationStatus.UNVERIFIED,
            message=f"Verification not supported for secret type: {secret_type}"
        )
    
    def get_supported_types(self) -> List[str]:
        """
        Get list of supported secret types for verification.
        
        Returns:
            List of secret type strings that can be verified
        """
        return [
            "aws_access_key", "aws_secret_key",
            "github_token", "github_pat", "github_fine_grained_pat", "github_oauth", "github_app_token",
            "gitlab_token", "gitlab_pat", "gitlab_pipeline_token",
            "slack_bot_token", "slack_user_token", "slack_webhook",
            "stripe_api_key", "stripe", "stripe_restricted",
            "twilio_api_key", "twilio",
            "sendgrid_api_key", "sendgrid",
            "openai_api_key", "openai",
            "anthropic_api_key", "anthropic",
            "huggingface_token", "huggingface",
            "mailchimp_api_key", "mailchimp",
            "mailgun_api_key", "mailgun",
            "datadog_api_key", "datadog",
            "newrelic_api_key", "newrelic",
            "heroku_api_key", "heroku",
            "digitalocean_pat", "digitalocean",
            "npm_token", "npm",
            "pypi_token", "pypi",
            "discord_webhook", "discord_bot_token",
            "shopify_token", "shopify",
            "notion",
            "airtable",
            "asana",
            "linear",
            "sentry_dsn", "sentry",
            "vault_token",
            "doppler_token",
            "supabase",
            "planetscale_password",
            "vercel",
            "netlify_token",
            "flyio_token",
            "cloudflare",
            "firebase",
            "mongodb_connection",
        ]
    
    async def verify_secret(self, secret_type: str, secret_value: str, extra_data: Optional[Dict[str, Any]] = None) -> Optional[bool]:
        """
        Verify a single secret by type and value.
        
        Args:
            secret_type: Type of secret (e.g., 'github_token', 'stripe_api_key')
            secret_value: The secret value to verify
            extra_data: Optional additional data needed for verification (e.g., secret_key for AWS)
            
        Returns:
            True if active, False if inactive, None if unknown/unsupported
        """
        from deployguard.core.models import Finding
        
        # Create a minimal Finding object for the verifier
        finding = Finding(
            pattern_id=secret_type,
            pattern_name=secret_type,
            file_path="<api>",
            line_number=0,
            matched_text=secret_value[:20] + "..." if len(secret_value) > 20 else secret_value,
            severity="high",
            type="secret",
            secret_type=secret_type,
            value=secret_value,
        )
        
        result = await self.verify_finding(finding)
        
        if result.status == VerificationStatus.VERIFIED_ACTIVE:
            return True
        elif result.status == VerificationStatus.VERIFIED_INACTIVE:
            return False
        else:
            return None
    
    # =========================================================================
    # AWS Verification
    # =========================================================================
    async def _verify_aws_key(self, finding: Finding, secret: str) -> VerificationResult:
        """Verify AWS access key by calling STS GetCallerIdentity."""
        # AWS access keys start with AKIA, ASIA, ABIA, or ACCA
        if not re.match(r'^(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}$', secret):
            return VerificationResult(
                finding=finding,
                status=VerificationStatus.UNVERIFIED,
                message="Invalid AWS access key format"
            )
        
        # For AWS, we need both access key and secret key
        # This is a format check only - full verification would need the secret key
        return VerificationResult(
            finding=finding,
            status=VerificationStatus.UNVERIFIED,
            message="AWS key verification requires both access key and secret key pair"
        )
    
    # =========================================================================
    # GitHub Verification
    # =========================================================================
    async def _verify_github_token(self, finding: Finding, token: str) -> VerificationResult:
        """Verify GitHub token by calling the user endpoint."""
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        
        async with self._session.get("https://api.github.com/user", headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message=f"GitHub token is valid (user: {data.get('login', 'unknown')})",
                    details={"user": data.get("login"), "scopes": resp.headers.get("X-OAuth-Scopes", "")}
                )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="GitHub token is invalid or expired"
                )
            elif resp.status == 403:
                # Could be rate limited or insufficient permissions
                if "rate limit" in (await resp.text()).lower():
                    return VerificationResult(
                        finding=finding,
                        status=VerificationStatus.RATE_LIMITED,
                        message="GitHub API rate limit exceeded"
                    )
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message="GitHub token is valid but has limited permissions"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    async def _verify_github_app_token(self, finding: Finding, token: str) -> VerificationResult:
        """Verify GitHub App installation token."""
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json"
        }
        
        async with self._session.get("https://api.github.com/app", headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message=f"GitHub App token is valid (app: {data.get('name', 'unknown')})",
                    details={"app_name": data.get("name"), "app_id": data.get("id")}
                )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="GitHub App token is invalid or expired"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    # =========================================================================
    # GitLab Verification
    # =========================================================================
    async def _verify_gitlab_token(self, finding: Finding, token: str) -> VerificationResult:
        """Verify GitLab token by calling the user endpoint."""
        headers = {"PRIVATE-TOKEN": token}
        
        async with self._session.get("https://gitlab.com/api/v4/user", headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message=f"GitLab token is valid (user: {data.get('username', 'unknown')})",
                    details={"username": data.get("username"), "email": data.get("email")}
                )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="GitLab token is invalid or expired"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    # =========================================================================
    # Slack Verification
    # =========================================================================
    async def _verify_slack_token(self, finding: Finding, token: str) -> VerificationResult:
        """Verify Slack token by calling auth.test."""
        async with self._session.post(
            "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {token}"}
        ) as resp:
            data = await resp.json()
            if data.get("ok"):
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message=f"Slack token is valid (team: {data.get('team', 'unknown')})",
                    details={"team": data.get("team"), "user": data.get("user")}
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message=f"Slack token is invalid: {data.get('error', 'unknown error')}"
                )
    
    async def _verify_slack_webhook(self, finding: Finding, webhook_url: str) -> VerificationResult:
        """Verify Slack webhook by sending a test message."""
        # Don't actually send messages in verification - just check URL format
        if re.match(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+', webhook_url):
            return VerificationResult(
                finding=finding,
                status=VerificationStatus.UNVERIFIED,
                message="Slack webhook URL format is valid (not tested to avoid sending messages)"
            )
        return VerificationResult(
            finding=finding,
            status=VerificationStatus.VERIFIED_INACTIVE,
            message="Invalid Slack webhook URL format"
        )
    
    # =========================================================================
    # Stripe Verification
    # =========================================================================
    async def _verify_stripe_key(self, finding: Finding, key: str) -> VerificationResult:
        """Verify Stripe API key."""
        auth = base64.b64encode(f"{key}:".encode()).decode()
        headers = {"Authorization": f"Basic {auth}"}
        
        async with self._session.get("https://api.stripe.com/v1/balance", headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message="Stripe API key is valid",
                    details={"livemode": data.get("livemode", False)}
                )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="Stripe API key is invalid"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    # =========================================================================
    # Twilio Verification
    # =========================================================================
    async def _verify_twilio_key(self, finding: Finding, key: str) -> VerificationResult:
        """Verify Twilio API key (requires Account SID and Auth Token pair)."""
        # Twilio requires both Account SID and Auth Token
        return VerificationResult(
            finding=finding,
            status=VerificationStatus.UNVERIFIED,
            message="Twilio verification requires Account SID and Auth Token pair"
        )
    
    # =========================================================================
    # SendGrid Verification
    # =========================================================================
    async def _verify_sendgrid_key(self, finding: Finding, key: str) -> VerificationResult:
        """Verify SendGrid API key."""
        headers = {"Authorization": f"Bearer {key}"}
        
        async with self._session.get("https://api.sendgrid.com/v3/user/profile", headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message="SendGrid API key is valid",
                    details={"username": data.get("username")}
                )
            elif resp.status in [401, 403]:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="SendGrid API key is invalid"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    # =========================================================================
    # OpenAI Verification
    # =========================================================================
    async def _verify_openai_key(self, finding: Finding, key: str) -> VerificationResult:
        """Verify OpenAI API key."""
        headers = {"Authorization": f"Bearer {key}"}
        
        async with self._session.get("https://api.openai.com/v1/models", headers=headers) as resp:
            if resp.status == 200:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message="OpenAI API key is valid"
                )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="OpenAI API key is invalid"
                )
            elif resp.status == 429:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.RATE_LIMITED,
                    message="OpenAI API rate limited (key may be valid)"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    # =========================================================================
    # Anthropic Verification
    # =========================================================================
    async def _verify_anthropic_key(self, finding: Finding, key: str) -> VerificationResult:
        """Verify Anthropic API key."""
        headers = {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }
        
        # Use a minimal request to check authentication
        payload = {
            "model": "claude-3-haiku-20240307",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "hi"}]
        }
        
        async with self._session.post(
            "https://api.anthropic.com/v1/messages",
            headers=headers,
            json=payload
        ) as resp:
            if resp.status == 200:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message="Anthropic API key is valid"
                )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="Anthropic API key is invalid"
                )
            elif resp.status == 429:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.RATE_LIMITED,
                    message="Anthropic API rate limited (key may be valid)"
                )
            else:
                # 400 could mean invalid model but valid key
                if resp.status == 400:
                    return VerificationResult(
                        finding=finding,
                        status=VerificationStatus.VERIFIED_ACTIVE,
                        message="Anthropic API key appears valid (request error)"
                    )
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    # =========================================================================
    # HuggingFace Verification
    # =========================================================================
    async def _verify_huggingface_token(self, finding: Finding, token: str) -> VerificationResult:
        """Verify HuggingFace token."""
        headers = {"Authorization": f"Bearer {token}"}
        
        async with self._session.get("https://huggingface.co/api/whoami-v2", headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message=f"HuggingFace token is valid (user: {data.get('name', 'unknown')})",
                    details={"name": data.get("name"), "type": data.get("type")}
                )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="HuggingFace token is invalid"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    # =========================================================================
    # Email Service Verification (Mailchimp, Mailgun)
    # =========================================================================
    async def _verify_mailchimp_key(self, finding: Finding, key: str) -> VerificationResult:
        """Verify Mailchimp API key."""
        # Mailchimp keys end with -usX where X is the datacenter
        match = re.search(r'-us(\d+)$', key)
        if not match:
            return VerificationResult(
                finding=finding,
                status=VerificationStatus.UNVERIFIED,
                message="Invalid Mailchimp API key format"
            )
        
        dc = match.group(1)
        auth = base64.b64encode(f"anystring:{key}".encode()).decode()
        headers = {"Authorization": f"Basic {auth}"}
        
        async with self._session.get(
            f"https://us{dc}.api.mailchimp.com/3.0/",
            headers=headers
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message=f"Mailchimp API key is valid (account: {data.get('account_name', 'unknown')})",
                    details={"account_name": data.get("account_name")}
                )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="Mailchimp API key is invalid"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    async def _verify_mailgun_key(self, finding: Finding, key: str) -> VerificationResult:
        """Verify Mailgun API key."""
        auth = base64.b64encode(f"api:{key}".encode()).decode()
        headers = {"Authorization": f"Basic {auth}"}
        
        async with self._session.get("https://api.mailgun.net/v3/domains", headers=headers) as resp:
            if resp.status == 200:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message="Mailgun API key is valid"
                )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="Mailgun API key is invalid"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    # =========================================================================
    # Monitoring Service Verification (Datadog, New Relic)
    # =========================================================================
    async def _verify_datadog_key(self, finding: Finding, key: str) -> VerificationResult:
        """Verify Datadog API key."""
        headers = {"DD-API-KEY": key}
        
        async with self._session.get(
            "https://api.datadoghq.com/api/v1/validate",
            headers=headers
        ) as resp:
            if resp.status == 200:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message="Datadog API key is valid"
                )
            elif resp.status == 403:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="Datadog API key is invalid"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    async def _verify_newrelic_key(self, finding: Finding, key: str) -> VerificationResult:
        """Verify New Relic API key."""
        headers = {"Api-Key": key}
        
        # Try NerdGraph API
        async with self._session.post(
            "https://api.newrelic.com/graphql",
            headers=headers,
            json={"query": "{ actor { user { email } } }"}
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get("data"):
                    return VerificationResult(
                        finding=finding,
                        status=VerificationStatus.VERIFIED_ACTIVE,
                        message="New Relic API key is valid"
                    )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="New Relic API key is invalid"
                )
            
            return VerificationResult(
                finding=finding,
                status=VerificationStatus.ERROR,
                message=f"Unexpected response: {resp.status}"
            )
    
    # =========================================================================
    # Cloud Platform Verification (Heroku, DigitalOcean, Vercel, Netlify)
    # =========================================================================
    async def _verify_heroku_key(self, finding: Finding, key: str) -> VerificationResult:
        """Verify Heroku API key."""
        headers = {
            "Authorization": f"Bearer {key}",
            "Accept": "application/vnd.heroku+json; version=3"
        }
        
        async with self._session.get("https://api.heroku.com/account", headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message=f"Heroku API key is valid (email: {data.get('email', 'unknown')})",
                    details={"email": data.get("email")}
                )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="Heroku API key is invalid"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    async def _verify_digitalocean_token(self, finding: Finding, token: str) -> VerificationResult:
        """Verify DigitalOcean token."""
        headers = {"Authorization": f"Bearer {token}"}
        
        async with self._session.get("https://api.digitalocean.com/v2/account", headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                account = data.get("account", {})
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message=f"DigitalOcean token is valid (email: {account.get('email', 'unknown')})",
                    details={"email": account.get("email")}
                )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="DigitalOcean token is invalid"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    async def _verify_vercel_token(self, finding: Finding, token: str) -> VerificationResult:
        """Verify Vercel token."""
        headers = {"Authorization": f"Bearer {token}"}
        
        async with self._session.get("https://api.vercel.com/v2/user", headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message=f"Vercel token is valid (user: {data.get('user', {}).get('username', 'unknown')})"
                )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="Vercel token is invalid"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    async def _verify_netlify_token(self, finding: Finding, token: str) -> VerificationResult:
        """Verify Netlify token."""
        headers = {"Authorization": f"Bearer {token}"}
        
        async with self._session.get("https://api.netlify.com/api/v1/user", headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message=f"Netlify token is valid (email: {data.get('email', 'unknown')})"
                )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="Netlify token is invalid"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    async def _verify_flyio_token(self, finding: Finding, token: str) -> VerificationResult:
        """Verify Fly.io token."""
        headers = {"Authorization": f"Bearer {token}"}
        
        async with self._session.get("https://api.fly.io/graphql", headers=headers) as resp:
            if resp.status == 200:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message="Fly.io token is valid"
                )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="Fly.io token is invalid"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    async def _verify_cloudflare_token(self, finding: Finding, token: str) -> VerificationResult:
        """Verify Cloudflare token."""
        headers = {"Authorization": f"Bearer {token}"}
        
        async with self._session.get(
            "https://api.cloudflare.com/client/v4/user/tokens/verify",
            headers=headers
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get("success"):
                    return VerificationResult(
                        finding=finding,
                        status=VerificationStatus.VERIFIED_ACTIVE,
                        message="Cloudflare token is valid"
                    )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="Cloudflare token is invalid"
                )
            
            return VerificationResult(
                finding=finding,
                status=VerificationStatus.ERROR,
                message=f"Unexpected response: {resp.status}"
            )
    
    # =========================================================================
    # Package Registry Verification (NPM, PyPI)
    # =========================================================================
    async def _verify_npm_token(self, finding: Finding, token: str) -> VerificationResult:
        """Verify NPM token."""
        headers = {"Authorization": f"Bearer {token}"}
        
        async with self._session.get("https://registry.npmjs.org/-/whoami", headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message=f"NPM token is valid (user: {data.get('username', 'unknown')})"
                )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="NPM token is invalid"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    async def _verify_pypi_token(self, finding: Finding, token: str) -> VerificationResult:
        """Verify PyPI token by checking format (no API for verification)."""
        if token.startswith("pypi-"):
            return VerificationResult(
                finding=finding,
                status=VerificationStatus.UNVERIFIED,
                message="PyPI token format is valid (no verification API available)"
            )
        return VerificationResult(
            finding=finding,
            status=VerificationStatus.VERIFIED_INACTIVE,
            message="Invalid PyPI token format"
        )
    
    # =========================================================================
    # Discord Verification
    # =========================================================================
    async def _verify_discord_webhook(self, finding: Finding, webhook_url: str) -> VerificationResult:
        """Verify Discord webhook by getting webhook info."""
        async with self._session.get(webhook_url) as resp:
            if resp.status == 200:
                data = await resp.json()
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message=f"Discord webhook is valid (name: {data.get('name', 'unknown')})"
                )
            elif resp.status == 401 or resp.status == 404:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="Discord webhook is invalid or deleted"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    async def _verify_discord_bot_token(self, finding: Finding, token: str) -> VerificationResult:
        """Verify Discord bot token."""
        headers = {"Authorization": f"Bot {token}"}
        
        async with self._session.get("https://discord.com/api/v10/users/@me", headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message=f"Discord bot token is valid (bot: {data.get('username', 'unknown')})"
                )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="Discord bot token is invalid"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    # =========================================================================
    # Productivity Tools Verification (Notion, Airtable, Asana, Linear)
    # =========================================================================
    async def _verify_notion_token(self, finding: Finding, token: str) -> VerificationResult:
        """Verify Notion token."""
        headers = {
            "Authorization": f"Bearer {token}",
            "Notion-Version": "2022-06-28"
        }
        
        async with self._session.get("https://api.notion.com/v1/users/me", headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message=f"Notion token is valid (type: {data.get('type', 'unknown')})"
                )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="Notion token is invalid"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    async def _verify_airtable_key(self, finding: Finding, key: str) -> VerificationResult:
        """Verify Airtable API key."""
        headers = {"Authorization": f"Bearer {key}"}
        
        async with self._session.get("https://api.airtable.com/v0/meta/whoami", headers=headers) as resp:
            if resp.status == 200:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message="Airtable API key is valid"
                )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="Airtable API key is invalid"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    async def _verify_asana_token(self, finding: Finding, token: str) -> VerificationResult:
        """Verify Asana token."""
        headers = {"Authorization": f"Bearer {token}"}
        
        async with self._session.get("https://app.asana.com/api/1.0/users/me", headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                user = data.get("data", {})
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message=f"Asana token is valid (user: {user.get('name', 'unknown')})"
                )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="Asana token is invalid"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    async def _verify_linear_token(self, finding: Finding, token: str) -> VerificationResult:
        """Verify Linear API key."""
        headers = {
            "Authorization": token,
            "Content-Type": "application/json"
        }
        
        async with self._session.post(
            "https://api.linear.app/graphql",
            headers=headers,
            json={"query": "{ viewer { id email } }"}
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get("data", {}).get("viewer"):
                    return VerificationResult(
                        finding=finding,
                        status=VerificationStatus.VERIFIED_ACTIVE,
                        message="Linear API key is valid"
                    )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="Linear API key is invalid"
                )
            
            return VerificationResult(
                finding=finding,
                status=VerificationStatus.ERROR,
                message=f"Unexpected response: {resp.status}"
            )
    
    async def _verify_shopify_token(self, finding: Finding, token: str) -> VerificationResult:
        """Verify Shopify token (needs store domain)."""
        return VerificationResult(
            finding=finding,
            status=VerificationStatus.UNVERIFIED,
            message="Shopify token verification requires store domain"
        )
    
    # =========================================================================
    # Infrastructure Tools Verification (Sentry, Vault, Doppler)
    # =========================================================================
    async def _verify_sentry_dsn(self, finding: Finding, dsn: str) -> VerificationResult:
        """Verify Sentry DSN by checking format."""
        if re.match(r'https://[a-f0-9]+@[a-z0-9]+\.ingest\.sentry\.io/\d+', dsn):
            return VerificationResult(
                finding=finding,
                status=VerificationStatus.UNVERIFIED,
                message="Sentry DSN format is valid (not tested to avoid sending events)"
            )
        return VerificationResult(
            finding=finding,
            status=VerificationStatus.VERIFIED_INACTIVE,
            message="Invalid Sentry DSN format"
        )
    
    async def _verify_vault_token(self, finding: Finding, token: str) -> VerificationResult:
        """Verify Vault token (requires Vault server address)."""
        return VerificationResult(
            finding=finding,
            status=VerificationStatus.UNVERIFIED,
            message="Vault token verification requires server address"
        )
    
    async def _verify_doppler_token(self, finding: Finding, token: str) -> VerificationResult:
        """Verify Doppler token."""
        auth = base64.b64encode(f"{token}:".encode()).decode()
        headers = {"Authorization": f"Basic {auth}"}
        
        async with self._session.get("https://api.doppler.com/v3/me", headers=headers) as resp:
            if resp.status == 200:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_ACTIVE,
                    message="Doppler token is valid"
                )
            elif resp.status == 401:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.VERIFIED_INACTIVE,
                    message="Doppler token is invalid"
                )
            else:
                return VerificationResult(
                    finding=finding,
                    status=VerificationStatus.ERROR,
                    message=f"Unexpected response: {resp.status}"
                )
    
    # =========================================================================
    # Database Verification (Supabase, PlanetScale, MongoDB)
    # =========================================================================
    async def _verify_supabase_key(self, finding: Finding, key: str) -> VerificationResult:
        """Verify Supabase key (requires project URL)."""
        return VerificationResult(
            finding=finding,
            status=VerificationStatus.UNVERIFIED,
            message="Supabase key verification requires project URL"
        )
    
    async def _verify_planetscale(self, finding: Finding, password: str) -> VerificationResult:
        """Verify PlanetScale credentials (requires full connection string)."""
        return VerificationResult(
            finding=finding,
            status=VerificationStatus.UNVERIFIED,
            message="PlanetScale verification requires full connection string"
        )
    
    async def _verify_mongodb_connection(self, finding: Finding, connection_string: str) -> VerificationResult:
        """Verify MongoDB connection string format."""
        if re.match(r'mongodb(\+srv)?://[^:]+:[^@]+@[^/]+', connection_string):
            return VerificationResult(
                finding=finding,
                status=VerificationStatus.UNVERIFIED,
                message="MongoDB connection string format is valid (not tested to avoid connecting)"
            )
        return VerificationResult(
            finding=finding,
            status=VerificationStatus.VERIFIED_INACTIVE,
            message="Invalid MongoDB connection string format"
        )
    
    async def _verify_firebase_key(self, finding: Finding, key: str) -> VerificationResult:
        """Verify Firebase API key (limited verification)."""
        # Firebase API keys are tied to projects, need project ID to fully verify
        return VerificationResult(
            finding=finding,
            status=VerificationStatus.UNVERIFIED,
            message="Firebase API key verification requires project configuration"
        )


def verify_secrets_sync(findings: List[Finding], timeout: int = 10, max_concurrent: int = 5) -> List[VerificationResult]:
    """
    Synchronous wrapper for verifying secrets.
    
    Args:
        findings: List of findings to verify
        timeout: Request timeout in seconds
        max_concurrent: Maximum concurrent verification requests
        
    Returns:
        List of verification results
    """
    async def _verify():
        verifier = SecretVerifier(timeout=timeout, max_concurrent=max_concurrent)
        return await verifier.verify_findings(findings)
    
    return asyncio.run(_verify())
