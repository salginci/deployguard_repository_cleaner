"""Core domain models for DeployGuard."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional
from uuid import UUID, uuid4


class Severity(str, Enum):
    """Security finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecretType(str, Enum):
    """Types of secrets that can be detected."""

    # Cloud credentials - AWS
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    AWS_KEY = "aws_key"
    AWS_SECRET = "aws_secret"
    AWS_BEDROCK_KEY = "aws_bedrock_key"
    
    # Cloud credentials - GCP
    GCP_API_KEY = "gcp_api_key"
    GCP_SERVICE_ACCOUNT = "gcp_service_account"
    
    # Cloud credentials - Azure
    AZURE_CLIENT_SECRET = "azure_client_secret"
    AZURE_CONNECTION_STRING = "azure_connection_string"
    
    # Cloud credentials - Alibaba
    ALIBABA_ACCESS_KEY = "alibaba_access_key"
    
    # Version Control - GitHub
    GITHUB_TOKEN = "github_token"
    GITHUB_APP_TOKEN = "github_app_token"
    GITHUB_FINE_GRAINED_PAT = "github_fine_grained_pat"
    
    # Version Control - GitLab
    GITLAB_TOKEN = "gitlab_token"
    GITLAB_RUNNER_TOKEN = "gitlab_runner_token"
    GITLAB_DEPLOY_TOKEN = "gitlab_deploy_token"
    
    # Version Control - Bitbucket
    BITBUCKET_TOKEN = "bitbucket_token"
    
    # AI/ML Services
    OPENAI_API_KEY = "openai_api_key"
    ANTHROPIC_API_KEY = "anthropic_api_key"
    COHERE_API_KEY = "cohere_api_key"
    HUGGINGFACE_TOKEN = "huggingface_token"
    PERPLEXITY_API_KEY = "perplexity_api_key"
    
    # Payment Services
    STRIPE_API_KEY = "stripe_api_key"
    STRIPE_WEBHOOK_SECRET = "stripe_webhook_secret"
    SQUARE_ACCESS_TOKEN = "square_access_token"
    PLAID_API_TOKEN = "plaid_api_token"
    
    # Communication Services
    SLACK_BOT_TOKEN = "slack_bot_token"
    SLACK_USER_TOKEN = "slack_user_token"
    SLACK_WEBHOOK = "slack_webhook"
    DISCORD_WEBHOOK = "discord_webhook"
    TWILIO_API_KEY = "twilio_api_key"
    SENDGRID_API_KEY = "sendgrid_api_key"
    MAILCHIMP_API_KEY = "mailchimp_api_key"
    MAILGUN_API_KEY = "mailgun_api_key"
    
    # Database
    DATABASE_CONNECTION = "database_connection"
    DATABASE_URL = "database_url"
    DATABASE_PASSWORD = "database_password"
    DATABASE_HOST = "database_host"
    DATABASE_NAME = "database_name"
    DATABASE_USER = "database_user"
    DATABASE_PORT = "database_port"
    PLANETSCALE_PASSWORD = "planetscale_password"
    
    # CI/CD
    TRAVIS_TOKEN = "travis_token"
    NETLIFY_TOKEN = "netlify_token"
    
    # Infrastructure
    TERRAFORM_TOKEN = "terraform_token"
    VAULT_TOKEN = "vault_token"
    DOPPLER_TOKEN = "doppler_token"
    PULUMI_TOKEN = "pulumi_token"
    HEROKU_API_KEY = "heroku_api_key"
    DIGITALOCEAN_PAT = "digitalocean_pat"
    FLYIO_TOKEN = "flyio_token"
    
    # Monitoring
    DATADOG_API_KEY = "datadog_api_key"
    NEWRELIC_API_KEY = "newrelic_api_key"
    NEWRELIC_INSERT_KEY = "newrelic_insert_key"
    SENTRY_DSN = "sentry_dsn"
    GRAFANA_API_KEY = "grafana_api_key"
    GRAFANA_CLOUD_TOKEN = "grafana_cloud_token"
    DYNATRACE_TOKEN = "dynatrace_token"
    SNYK_TOKEN = "snyk_token"
    
    # Package Registries
    NPM_TOKEN = "npm_token"
    PYPI_TOKEN = "pypi_token"
    RUBYGEMS_TOKEN = "rubygems_token"
    CLOJARS_TOKEN = "clojars_token"
    
    # Keys and secrets
    PRIVATE_KEY = "private_key"
    SSH_KEY = "ssh_key"
    AGE_SECRET_KEY = "age_secret_key"
    API_KEY = "api_key"
    SECRET_KEY = "secret_key"
    PRIVATE_TOKEN = "private_token"
    CLIENT_SECRET = "client_secret"
    ACCESS_TOKEN = "access_token"
    
    # Authentication
    PASSWORD = "password"
    USERNAME = "username"
    CREDENTIALS = "credentials"
    AUTH_TOKEN = "auth_token"
    BEARER_TOKEN = "bearer_token"
    JWT = "jwt"
    
    # Network/Infrastructure
    HOSTNAME = "hostname"
    IP_ADDRESS = "ip_address"
    PORT = "port"
    URL = "url"
    ENDPOINT = "endpoint"
    URL_WITH_CREDENTIALS = "url_with_credentials"
    
    # Social Media
    FACEBOOK_TOKEN = "facebook_token"
    FACEBOOK_PAGE_TOKEN = "facebook_page_token"
    TWITTER_API_KEY = "twitter_api_key"
    
    # E-Commerce
    SHOPIFY_TOKEN = "shopify_token"
    SHOPIFY_CUSTOM_TOKEN = "shopify_custom_token"
    SHOPIFY_PRIVATE_TOKEN = "shopify_private_token"
    SHOPIFY_SHARED_SECRET = "shopify_shared_secret"
    
    # CDN/Cloud
    CLOUDFLARE_API_KEY = "cloudflare_api_key"
    CLOUDFLARE_ORIGIN_KEY = "cloudflare_origin_key"
    FASTLY_API_KEY = "fastly_api_key"
    
    # Search
    ALGOLIA_API_KEY = "algolia_api_key"
    
    # Message Queues
    RABBITMQ_CONNECTION = "rabbitmq_connection"
    
    # Special Tokens
    ONEPASSWORD_SECRET = "1password_secret"
    ONEPASSWORD_SERVICE_TOKEN = "1password_service_token"
    NOTION_TOKEN = "notion_token"
    OKTA_TOKEN = "okta_token"
    MAPBOX_TOKEN = "mapbox_token"
    POSTMAN_TOKEN = "postman_token"
    DATABRICKS_TOKEN = "databricks_token"
    JFROG_API_KEY = "jfrog_api_key"
    LINEAR_API_KEY = "linear_api_key"
    INFRACOST_TOKEN = "infracost_token"
    EASYPOST_TOKEN = "easypost_token"
    FRAMEIO_TOKEN = "frameio_token"
    README_TOKEN = "readme_token"
    PREFECT_TOKEN = "prefect_token"
    
    # Cryptocurrency
    COINBASE_TOKEN = "coinbase_token"
    BINANCE_API_KEY = "binance_api_key"
    KRAKEN_TOKEN = "kraken_token"
    
    # Atlassian
    ATLASSIAN_TOKEN = "atlassian_token"
    
    # Kubernetes
    KUBERNETES_SECRET = "kubernetes_secret"
    OPENSHIFT_TOKEN = "openshift_token"
    
    # Other secrets
    JWT_TOKEN = "jwt_token"
    OAUTH_SECRET = "oauth_secret"
    ENCRYPTION_KEY = "encryption_key"
    CERTIFICATE = "certificate"
    GENERIC_SECRET = "generic_secret"
    HARDCODED_VALUE = "hardcoded_value"
    UNKNOWN = "unknown"


class Platform(str, Enum):
    """Supported Git platforms."""

    GITHUB = "github"
    BITBUCKET = "bitbucket"
    GITLAB = "gitlab"
    AZURE_DEVOPS = "azure_devops"


class ScanStatus(str, Enum):
    """Scan execution status."""

    PENDING = "pending"
    CLONING = "cloning"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CleanupStatus(str, Enum):
    """Cleanup execution status."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class Repository:
    """Represents a Git repository."""

    id: UUID = field(default_factory=uuid4)
    platform: Platform = Platform.GITHUB
    owner: str = ""
    name: str = ""
    full_name: str = ""
    url: str = ""
    default_branch: str = "main"
    is_private: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate and set full_name if not provided."""
        if not self.full_name and self.owner and self.name:
            self.full_name = f"{self.owner}/{self.name}"

    @property
    def clone_url(self) -> str:
        """Get the clone URL for the repository."""
        if self.url:
            return self.url
        # Construct URL based on platform
        if self.platform == Platform.GITHUB:
            return f"https://github.com/{self.full_name}.git"
        elif self.platform == Platform.BITBUCKET:
            return f"https://bitbucket.org/{self.full_name}.git"
        elif self.platform == Platform.GITLAB:
            return f"https://gitlab.com/{self.full_name}.git"
        return ""


@dataclass
class Finding:
    """Represents a detected secret or security issue."""

    id: UUID = field(default_factory=uuid4)
    scan_id: UUID = field(default_factory=uuid4)
    type: SecretType = SecretType.GENERIC_SECRET
    severity: Severity = Severity.MEDIUM
    file_path: str = ""
    line_number: int = 0
    column_start: int = 0
    column_end: int = 0
    branch: str = "main"
    commit_hash: str = ""
    commit_date: Optional[datetime] = None
    exposed_value: str = ""
    exposed_value_hash: str = ""
    suggested_variable: str = ""
    context: str = ""
    description: str = ""
    remediation: str = ""
    false_positive: bool = False
    reviewed: bool = False
    reviewed_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, any] = field(default_factory=dict)

    def mask_value(self, show_chars: int = 4) -> str:
        """Return a masked version of the exposed value."""
        if len(self.exposed_value) <= show_chars * 2:
            return "*" * len(self.exposed_value)
        return (
            f"{self.exposed_value[:show_chars]}"
            f"{'*' * (len(self.exposed_value) - show_chars * 2)}"
            f"{self.exposed_value[-show_chars:]}"
        )


@dataclass
class ScanResult:
    """Represents the result of a repository scan."""

    id: UUID = field(default_factory=uuid4)
    repository_id: UUID = field(default_factory=uuid4)
    status: ScanStatus = ScanStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    branches_scanned: List[str] = field(default_factory=list)
    commits_scanned: int = 0
    files_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)
    error_message: Optional[str] = None
    scan_options: Dict[str, any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def duration_seconds(self) -> Optional[float]:
        """Calculate scan duration in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def findings_by_severity(self) -> Dict[Severity, int]:
        """Count findings grouped by severity."""
        counts: Dict[Severity, int] = {severity: 0 for severity in Severity}
        for finding in self.findings:
            if not finding.false_positive:
                counts[finding.severity] += 1
        return counts

    @property
    def total_findings(self) -> int:
        """Total number of non-false-positive findings."""
        return sum(1 for f in self.findings if not f.false_positive)


@dataclass
class CleanupJob:
    """Represents a cleanup/remediation job."""

    id: UUID = field(default_factory=uuid4)
    scan_id: UUID = field(default_factory=uuid4)
    status: CleanupStatus = CleanupStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    findings_to_clean: List[UUID] = field(default_factory=list)
    findings_cleaned: int = 0
    files_modified: List[str] = field(default_factory=list)
    commits_modified: int = 0
    backup_branch: Optional[str] = None
    dry_run: bool = False
    error_message: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, any] = field(default_factory=dict)


@dataclass
class VariableMapping:
    """Maps an exposed secret to an environment variable."""

    id: UUID = field(default_factory=uuid4)
    finding_id: UUID = field(default_factory=uuid4)
    original_value_hash: str = ""
    variable_name: str = ""
    variable_description: str = ""
    example_value: str = ""
    is_sensitive: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PublishJob:
    """Represents a job to publish cleaned code to a target repository."""

    id: UUID = field(default_factory=uuid4)
    scan_id: UUID = field(default_factory=uuid4)
    cleanup_job_id: UUID = field(default_factory=uuid4)
    target_platform: Platform = Platform.GITHUB
    target_repository: str = ""
    target_url: str = ""
    create_repo: bool = False
    upload_secrets: bool = False
    status: str = "pending"
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, any] = field(default_factory=dict)
