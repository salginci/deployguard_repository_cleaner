"""
Domain Value Objects

Value Objects are immutable, identified by their attributes (not identity).
They encapsulate validation and ensure data integrity.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional
import re
import hashlib


class JobStatus(str, Enum):
    """
    Job lifecycle states.
    
    State Machine:
    PENDING -> CLONING -> SCANNING -> AWAITING_SELECTION -> CLEANING -> 
    CLEAN_COMPLETE -> PUSHING -> COMPLETED
    
    Any state can transition to FAILED or CANCELLED
    """
    PENDING = "pending"
    CLONING = "cloning"
    SCANNING = "scanning"
    SCAN_COMPLETE = "scan_complete"
    AWAITING_SELECTION = "awaiting_selection"
    CLEANING = "cleaning"
    CLEAN_COMPLETE = "clean_complete"
    UPLOADING = "uploading"
    PUSHING = "pushing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    
    def can_transition_to(self, target: 'JobStatus') -> bool:
        """Check if transition to target state is valid."""
        # Failed and Cancelled are terminal states but can be reached from any state
        if target in (JobStatus.FAILED, JobStatus.CANCELLED):
            return self not in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED)
        
        # Define valid transitions
        valid_transitions = {
            JobStatus.PENDING: [JobStatus.CLONING],
            JobStatus.CLONING: [JobStatus.SCANNING],
            JobStatus.SCANNING: [JobStatus.SCAN_COMPLETE, JobStatus.AWAITING_SELECTION],
            JobStatus.SCAN_COMPLETE: [JobStatus.AWAITING_SELECTION],
            JobStatus.AWAITING_SELECTION: [JobStatus.CLEANING],
            JobStatus.CLEANING: [JobStatus.CLEAN_COMPLETE, JobStatus.UPLOADING],
            JobStatus.CLEAN_COMPLETE: [JobStatus.PUSHING],
            JobStatus.UPLOADING: [JobStatus.CLEAN_COMPLETE],
            JobStatus.PUSHING: [JobStatus.COMPLETED],
            JobStatus.COMPLETED: [],
            JobStatus.FAILED: [],
            JobStatus.CANCELLED: [],
        }
        return target in valid_transitions.get(self, [])
    
    @property
    def is_terminal(self) -> bool:
        """Check if this is a terminal state."""
        return self in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED)
    
    @property
    def is_active(self) -> bool:
        """Check if job is actively processing."""
        return self in (
            JobStatus.CLONING, JobStatus.SCANNING, 
            JobStatus.CLEANING, JobStatus.UPLOADING, JobStatus.PUSHING
        )


class SecretType(str, Enum):
    """Types of secrets that can be detected."""
    PASSWORD = "password"
    API_KEY = "api_key"
    TOKEN = "token"
    PRIVATE_KEY = "private_key"
    CERTIFICATE = "certificate"
    CONNECTION_STRING = "connection_string"
    ENCRYPTION_KEY = "encryption_key"
    CREDENTIAL = "credential"
    AWS_KEY = "aws_key"
    AZURE_KEY = "azure_key"
    GCP_KEY = "gcp_key"
    SSH_KEY = "ssh_key"
    JWT = "jwt"
    OTHER = "other"
    
    @classmethod
    def from_pattern_name(cls, pattern: str) -> 'SecretType':
        """Infer secret type from pattern name."""
        pattern_lower = pattern.lower()
        
        mapping = {
            'password': cls.PASSWORD,
            'api_key': cls.API_KEY,
            'api-key': cls.API_KEY,
            'apikey': cls.API_KEY,
            'token': cls.TOKEN,
            'private_key': cls.PRIVATE_KEY,
            'private-key': cls.PRIVATE_KEY,
            'certificate': cls.CERTIFICATE,
            'cert': cls.CERTIFICATE,
            'connection_string': cls.CONNECTION_STRING,
            'connectionstring': cls.CONNECTION_STRING,
            'encryption': cls.ENCRYPTION_KEY,
            'credential': cls.CREDENTIAL,
            'aws': cls.AWS_KEY,
            'azure': cls.AZURE_KEY,
            'gcp': cls.GCP_KEY,
            'google': cls.GCP_KEY,
            'ssh': cls.SSH_KEY,
            'jwt': cls.JWT,
        }
        
        for key, secret_type in mapping.items():
            if key in pattern_lower:
                return secret_type
        return cls.OTHER


class Severity(str, Enum):
    """Secret severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    
    @property
    def score(self) -> int:
        """Numeric score for sorting."""
        scores = {
            Severity.CRITICAL: 100,
            Severity.HIGH: 80,
            Severity.MEDIUM: 50,
            Severity.LOW: 20,
            Severity.INFO: 0,
        }
        return scores[self]


@dataclass(frozen=True)
class JobId:
    """
    Unique identifier for a Job.
    
    Immutable value object that validates UUID format.
    """
    value: str
    
    def __post_init__(self):
        if not self._is_valid_uuid(self.value):
            raise ValueError(f"Invalid job ID format: {self.value}")
    
    @staticmethod
    def _is_valid_uuid(value: str) -> bool:
        uuid_pattern = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            re.IGNORECASE
        )
        return bool(uuid_pattern.match(value))
    
    @classmethod
    def generate(cls) -> 'JobId':
        """Generate a new unique JobId."""
        import uuid
        return cls(str(uuid.uuid4()))
    
    def __str__(self) -> str:
        return self.value
    
    def __eq__(self, other) -> bool:
        if isinstance(other, JobId):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other
        return False
    
    def __hash__(self) -> int:
        return hash(self.value)


@dataclass(frozen=True)
class UserId:
    """User identifier from external auth service."""
    value: str
    
    def __post_init__(self):
        if not self.value or len(self.value) > 255:
            raise ValueError(f"Invalid user ID: {self.value}")
    
    def __str__(self) -> str:
        return self.value
    
    def __eq__(self, other) -> bool:
        if isinstance(other, UserId):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other
        return False
    
    def __hash__(self) -> int:
        return hash(self.value)


@dataclass(frozen=True)
class SecretHash:
    """
    SHA256 hash of a secret value for deduplication.
    
    We never store the actual secret value, only its hash.
    """
    value: str
    
    def __post_init__(self):
        if len(self.value) != 64:
            raise ValueError("SecretHash must be 64 character SHA256 hex")
    
    @classmethod
    def from_secret(cls, secret_value: str, context: str = "") -> 'SecretHash':
        """Create hash from secret value and optional context."""
        data = f"{secret_value}:{context}".encode('utf-8')
        hash_value = hashlib.sha256(data).hexdigest()
        return cls(hash_value)
    
    def __str__(self) -> str:
        return self.value[:8] + "..."  # Only show prefix for logging


@dataclass(frozen=True)
class SecretPreview:
    """
    Masked preview of a secret value.
    
    Shows only first and last few characters.
    """
    value: str
    
    @classmethod
    def create(cls, secret_value: str, visible_chars: int = 3) -> 'SecretPreview':
        """Create a preview with masked middle portion."""
        if len(secret_value) <= visible_chars * 2 + 3:
            return cls("***")
        
        preview = f"{secret_value[:visible_chars]}...{secret_value[-visible_chars:]}"
        return cls(preview)
    
    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class RepositoryUrl:
    """Repository URL with validation."""
    value: str
    
    def __post_init__(self):
        if not self._is_valid_url(self.value):
            raise ValueError(f"Invalid repository URL: {self.value}")
    
    @staticmethod
    def _is_valid_url(url: str) -> bool:
        # Accept HTTPS, HTTP, SSH, and git protocols
        patterns = [
            r'^https?://[^\s]+\.git$',
            r'^https?://[^\s]+$',
            r'^git@[^\s]+:[^\s]+\.git$',
            r'^ssh://[^\s]+$',
        ]
        return any(re.match(p, url) for p in patterns)
    
    def with_credentials(self, token: str) -> str:
        """Return URL with embedded credentials."""
        if not token:
            return self.value
        
        if '://' in self.value:
            protocol, rest = self.value.split('://', 1)
            return f"{protocol}://{token}@{rest}"
        return self.value
    
    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Platform:
    """Git platform identifier."""
    value: str
    
    SUPPORTED = {'github', 'bitbucket', 'gitlab', 'azure_devops'}
    
    def __post_init__(self):
        if self.value.lower() not in self.SUPPORTED:
            raise ValueError(
                f"Unsupported platform: {self.value}. "
                f"Supported: {', '.join(self.SUPPORTED)}"
            )
        # Normalize to lowercase
        object.__setattr__(self, 'value', self.value.lower())
    
    def __str__(self) -> str:
        return self.value
