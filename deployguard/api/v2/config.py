"""
DeployGuard - Service Configuration
Handles graceful degradation when services are unavailable
"""

import os
from typing import Optional
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ExecutionMode(str, Enum):
    """Execution mode for DeployGuard"""
    CLI = "cli"           # Direct execution, no queue needed
    API_SYNC = "api_sync"  # API mode but execute synchronously (fallback)
    API_ASYNC = "api_async"  # Full async with Celery/RabbitMQ


@dataclass
class ServiceConfig:
    """Configuration for external services"""
    # Database
    database_url: str = "sqlite:///deployguard.db"
    
    # Message Broker (RabbitMQ)
    broker_url: Optional[str] = None
    broker_available: bool = False
    
    # Result Backend
    result_backend: Optional[str] = None
    
    # Object Storage (MinIO/S3)
    s3_endpoint: Optional[str] = None
    s3_access_key: Optional[str] = None
    s3_secret_key: Optional[str] = None
    s3_bucket: str = "deployguard"
    s3_available: bool = False
    
    # Auth Service
    auth_service_url: Optional[str] = None
    
    # Execution mode
    mode: ExecutionMode = ExecutionMode.CLI


def check_rabbitmq_connection(broker_url: str) -> bool:
    """Check if RabbitMQ is available"""
    if not broker_url:
        return False
    
    try:
        import pika
        # Parse AMQP URL
        params = pika.URLParameters(broker_url)
        connection = pika.BlockingConnection(params)
        connection.close()
        return True
    except Exception as e:
        logger.warning(f"RabbitMQ not available: {e}")
        return False


def check_s3_connection(endpoint: str, access_key: str, secret_key: str, bucket: str) -> bool:
    """Check if S3/MinIO is available"""
    if not all([endpoint, access_key, secret_key]):
        return False
    
    try:
        import boto3
        from botocore.client import Config
        
        client = boto3.client(
            's3',
            endpoint_url=endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=Config(signature_version='s3v4', connect_timeout=5, read_timeout=5),
            region_name='us-east-1'
        )
        # Try to access bucket
        client.head_bucket(Bucket=bucket)
        return True
    except Exception as e:
        logger.warning(f"S3/MinIO not available: {e}")
        return False


def get_config() -> ServiceConfig:
    """
    Get service configuration based on environment.
    Automatically detects available services.
    """
    config = ServiceConfig()
    
    # Database (required for API, optional for CLI)
    config.database_url = os.getenv(
        'DATABASE_URL', 
        'sqlite:///deployguard.db'
    )
    
    # Message Broker
    config.broker_url = os.getenv('CELERY_BROKER_URL')
    if config.broker_url:
        config.broker_available = check_rabbitmq_connection(config.broker_url)
    
    # Result Backend (defaults to database if not specified)
    config.result_backend = os.getenv(
        'CELERY_RESULT_BACKEND',
        f'db+{config.database_url}' if 'postgresql' in config.database_url else None
    )
    
    # S3/MinIO
    config.s3_endpoint = os.getenv('S3_ENDPOINT_URL')
    config.s3_access_key = os.getenv('S3_ACCESS_KEY')
    config.s3_secret_key = os.getenv('S3_SECRET_KEY')
    config.s3_bucket = os.getenv('S3_BUCKET', 'deployguard')
    
    if config.s3_endpoint:
        config.s3_available = check_s3_connection(
            config.s3_endpoint, config.s3_access_key, 
            config.s3_secret_key, config.s3_bucket
        )
    
    # Auth Service
    config.auth_service_url = os.getenv('AUTH_SERVICE_URL')
    
    # Determine execution mode
    if os.getenv('DEPLOYGUARD_MODE') == 'cli':
        config.mode = ExecutionMode.CLI
    elif config.broker_available and config.s3_available:
        config.mode = ExecutionMode.API_ASYNC
    elif os.getenv('DEPLOYGUARD_MODE') == 'api':
        config.mode = ExecutionMode.API_SYNC
        logger.warning("RabbitMQ/S3 not available, running in sync mode")
    else:
        config.mode = ExecutionMode.CLI
    
    return config


# Global config instance
_config: Optional[ServiceConfig] = None


def get_service_config() -> ServiceConfig:
    """Get or create service configuration"""
    global _config
    if _config is None:
        _config = get_config()
    return _config


def is_async_available() -> bool:
    """Check if async processing is available"""
    config = get_service_config()
    return config.mode == ExecutionMode.API_ASYNC


def require_async():
    """Raise error if async is not available"""
    if not is_async_available():
        raise RuntimeError(
            "Async processing not available. "
            "RabbitMQ and S3 must be configured and accessible."
        )
