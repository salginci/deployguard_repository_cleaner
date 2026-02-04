"""
Configuration management for DeployGuard
Handles credential storage and application settings
"""
import json
import os
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict


@dataclass
class DeployGuardConfig:
    """DeployGuard configuration"""
    github_token: Optional[str] = None
    bitbucket_username: Optional[str] = None
    bitbucket_app_password: Optional[str] = None
    default_output_dir: str = "./deployguard_reports"
    default_report_format: str = "text"
    scan_git_history: bool = False
    auto_cleanup: bool = False
    max_file_size_mb: int = 10
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DeployGuardConfig':
        """Create from dictionary"""
        return cls(**data)


class ConfigManager:
    """Manages DeployGuard configuration"""
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize config manager
        
        Args:
            config_path: Path to config file (defaults to ~/.deployguard/config.json)
        """
        if config_path is None:
            config_path = Path.home() / ".deployguard" / "config.json"
        
        self.config_path = config_path
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self._config: Optional[DeployGuardConfig] = None
    
    def load(self) -> DeployGuardConfig:
        """Load configuration from file"""
        if self._config is not None:
            return self._config
        
        if not self.config_path.exists():
            self._config = DeployGuardConfig()
            return self._config
        
        try:
            with open(self.config_path, 'r') as f:
                data = json.load(f)
                self._config = DeployGuardConfig.from_dict(data)
                return self._config
        except (json.JSONDecodeError, KeyError) as e:
            # If config is corrupted, start fresh
            self._config = DeployGuardConfig()
            return self._config
    
    def save(self, config: Optional[DeployGuardConfig] = None) -> None:
        """
        Save configuration to file
        
        Args:
            config: Configuration to save (uses current if None)
        """
        if config is not None:
            self._config = config
        
        if self._config is None:
            raise ValueError("No configuration to save")
        
        with open(self.config_path, 'w') as f:
            json.dump(self._config.to_dict(), f, indent=2)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        config = self.load()
        return getattr(config, key, default)
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value"""
        config = self.load()
        if hasattr(config, key):
            setattr(config, key, value)
            self.save(config)
        else:
            raise KeyError(f"Invalid config key: {key}")
    
    def update(self, **kwargs) -> None:
        """Update multiple configuration values"""
        config = self.load()
        for key, value in kwargs.items():
            if hasattr(config, key):
                setattr(config, key, value)
            else:
                raise KeyError(f"Invalid config key: {key}")
        self.save(config)
    
    def clear(self) -> None:
        """Clear all configuration"""
        self._config = DeployGuardConfig()
        self.save()
    
    def get_github_token(self) -> Optional[str]:
        """Get GitHub token (from config or environment)"""
        token = self.get('github_token')
        if token:
            return token
        return os.getenv('GITHUB_TOKEN')
    
    def get_bitbucket_credentials(self) -> tuple[Optional[str], Optional[str]]:
        """Get BitBucket credentials (from config or environment)"""
        username = self.get('bitbucket_username') or os.getenv('BITBUCKET_USERNAME')
        password = self.get('bitbucket_app_password') or os.getenv('BITBUCKET_APP_PASSWORD')
        return username, password
    
    def has_github_auth(self) -> bool:
        """Check if GitHub authentication is configured"""
        return self.get_github_token() is not None
    
    def has_bitbucket_auth(self) -> bool:
        """Check if BitBucket authentication is configured"""
        username, password = self.get_bitbucket_credentials()
        return username is not None and password is not None
