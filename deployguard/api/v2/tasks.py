"""
DeployGuard API v2 - Celery Worker Tasks
Background tasks for scanning, cleaning, and pushing repositories

NOTE: This module is ONLY used in API mode. The CLI operates directly
without any queue dependencies (RabbitMQ not required for CLI).
"""

import os
import shutil
import tempfile
import hashlib
import subprocess
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from celery import Celery, Task
from celery.utils.log import get_task_logger
from celery.exceptions import OperationalError
import boto3
from botocore.client import Config

from .models import (
    Job, SecretFound, JobStatus, SecretType, AuditLog,
    get_db_session
)

logger = get_task_logger(__name__)

# Celery Configuration
# Supports both RabbitMQ (recommended) and Redis as broker
# Result backend uses PostgreSQL (via SQLAlchemy) for durability
#
# IMPORTANT: This is only used in API mode. CLI does NOT require RabbitMQ.
# The celery_app is lazily initialized to prevent import failures in CLI mode.

def create_celery_app():
    """Create Celery app with broker connection.
    
    This is lazily called only when tasks are actually used (API mode).
    CLI mode imports this module but never calls tasks, so no broker needed.
    """
    app = Celery(
        'deployguard',
        broker=os.getenv('CELERY_BROKER_URL', 'amqp://guest:guest@localhost:5672//'),
        backend=os.getenv('CELERY_RESULT_BACKEND', 'db+postgresql://deployguard:password@localhost:5432/deployguard')
    )
    return app


# Lazy initialization - app is created when first accessed
_celery_app = None


def get_celery_app():
    """Get or create Celery app instance."""
    global _celery_app
    if _celery_app is None:
        _celery_app = create_celery_app()
        configure_celery(_celery_app)
    return _celery_app


# For backwards compatibility and Celery CLI (workers)
celery_app = Celery(
    'deployguard',
    broker=os.getenv('CELERY_BROKER_URL', 'amqp://guest:guest@localhost:5672//'),
    backend=os.getenv('CELERY_RESULT_BACKEND', 'db+postgresql://deployguard:password@localhost:5432/deployguard')
)


def configure_celery(app):
    """Configure Celery app settings."""
    app.conf.update(
        # Serialization
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        
        # Timezone
        timezone='UTC',
        enable_utc=True,
        
        # Task tracking
        task_track_started=True,
        task_time_limit=3600,  # 1 hour max per task
        task_soft_time_limit=3300,  # Soft limit 55 min (allows cleanup)
        
        # Reliability settings (important for long-running tasks)
        worker_prefetch_multiplier=1,  # One task at a time per worker
        task_acks_late=True,  # Ack after completion for reliability
        task_reject_on_worker_lost=True,  # Requeue if worker dies
        
        # RabbitMQ specific - connection resilience
        broker_connection_retry_on_startup=True,
        broker_connection_retry=True,
        broker_connection_max_retries=10,
        
        # RabbitMQ specific queues
        task_default_queue='deployguard',
        task_queues={
            'deployguard': {'exchange': 'deployguard', 'routing_key': 'deployguard'},
            'deployguard.scan': {'exchange': 'deployguard', 'routing_key': 'scan'},
            'deployguard.clean': {'exchange': 'deployguard', 'routing_key': 'clean'},
            'deployguard.push': {'exchange': 'deployguard', 'routing_key': 'push'},
        },
        
        # Result backend settings
        result_extended=True,  # Store task args/kwargs in result
        result_expires=86400,  # Results expire after 24 hours
    )


celery_app.conf.update(
    # Serialization
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    
    # Timezone
    timezone='UTC',
    enable_utc=True,
    
    # Task tracking
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max per task
    task_soft_time_limit=3300,  # Soft limit 55 min (allows cleanup)
    
    # Reliability settings (important for long-running tasks)
    worker_prefetch_multiplier=1,  # One task at a time per worker
    task_acks_late=True,  # Ack after completion for reliability
    task_reject_on_worker_lost=True,  # Requeue if worker dies
    
    # RabbitMQ connection resilience
    broker_connection_retry_on_startup=True,
    broker_connection_retry=True,
    broker_connection_max_retries=10,
    
    # RabbitMQ specific queues (ignored if using Redis)
    task_default_queue='deployguard',
    task_queues={
        'deployguard': {'exchange': 'deployguard', 'routing_key': 'deployguard'},
        'deployguard.scan': {'exchange': 'deployguard', 'routing_key': 'scan'},
        'deployguard.clean': {'exchange': 'deployguard', 'routing_key': 'clean'},
        'deployguard.push': {'exchange': 'deployguard', 'routing_key': 'push'},
    },
    
    # Result backend settings
    result_extended=True,  # Store task args/kwargs in result
    result_expires=86400,  # Results expire after 24 hours
)


# Apply same config to the factory function
configure_celery(celery_app)


def check_broker_connection() -> bool:
    """Check if broker (RabbitMQ) is available.
    
    Returns True if broker is connected, False otherwise.
    """
    try:
        celery_app.control.ping(timeout=2.0)
        return True
    except Exception:
        return False


class StorageClient:
    """MinIO/S3 compatible storage client"""
    
    def __init__(self):
        self.client = boto3.client(
            's3',
            endpoint_url=os.getenv('S3_ENDPOINT_URL', 'http://localhost:9000'),
            aws_access_key_id=os.getenv('S3_ACCESS_KEY', 'minioadmin'),
            aws_secret_access_key=os.getenv('S3_SECRET_KEY', 'minioadmin'),
            config=Config(signature_version='s3v4'),
            region_name='us-east-1'
        )
        self.bucket = os.getenv('S3_BUCKET', 'deployguard')
        self._ensure_bucket()
    
    def _ensure_bucket(self):
        """Create bucket if it doesn't exist"""
        try:
            self.client.head_bucket(Bucket=self.bucket)
        except:
            self.client.create_bucket(Bucket=self.bucket)
    
    def upload_directory(self, local_path: str, s3_prefix: str) -> str:
        """Upload a directory to S3"""
        for root, dirs, files in os.walk(local_path):
            for file in files:
                local_file = os.path.join(root, file)
                relative_path = os.path.relpath(local_file, local_path)
                s3_key = f"{s3_prefix}/{relative_path}"
                self.client.upload_file(local_file, self.bucket, s3_key)
        return s3_prefix
    
    def upload_file(self, local_path: str, s3_key: str) -> str:
        """Upload a single file to S3"""
        self.client.upload_file(local_path, self.bucket, s3_key)
        return s3_key
    
    def download_directory(self, s3_prefix: str, local_path: str):
        """Download a directory from S3"""
        paginator = self.client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=self.bucket, Prefix=s3_prefix):
            for obj in page.get('Contents', []):
                s3_key = obj['Key']
                relative_path = s3_key[len(s3_prefix):].lstrip('/')
                local_file = os.path.join(local_path, relative_path)
                os.makedirs(os.path.dirname(local_file), exist_ok=True)
                self.client.download_file(self.bucket, s3_key, local_file)
    
    def delete_prefix(self, s3_prefix: str):
        """Delete all objects under a prefix"""
        paginator = self.client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=self.bucket, Prefix=s3_prefix):
            objects = [{'Key': obj['Key']} for obj in page.get('Contents', [])]
            if objects:
                self.client.delete_objects(Bucket=self.bucket, Delete={'Objects': objects})
    
    def generate_presigned_url(self, s3_key: str, expiration: int = 3600) -> str:
        """Generate a presigned URL for download"""
        return self.client.generate_presigned_url(
            'get_object',
            Params={'Bucket': self.bucket, 'Key': s3_key},
            ExpiresIn=expiration
        )


class CredentialService:
    """Interface to external credential/auth service"""
    
    @staticmethod
    def get_credentials(credential_id: str, user_id: str) -> Dict[str, str]:
        """
        Fetch credentials from external auth service
        Returns dict with 'username' and 'token' or 'password'
        """
        # TODO: Implement actual call to your auth service
        # For now, return from environment or placeholder
        auth_service_url = os.getenv('AUTH_SERVICE_URL')
        
        if auth_service_url:
            import requests
            response = requests.get(
                f"{auth_service_url}/api/credentials/{credential_id}",
                headers={"X-User-ID": user_id}
            )
            if response.ok:
                return response.json()
        
        # Fallback for development
        return {
            "username": os.getenv('GIT_USERNAME', ''),
            "token": os.getenv('GIT_TOKEN', '')
        }


def update_job_status(job_id: str, status: JobStatus, message: str = None, 
                      progress: int = None, **extra_fields):
    """Update job status in database"""
    db = get_db_session(os.getenv('DATABASE_URL', 'sqlite:///deployguard.db'))
    try:
        job = db.query(Job).filter(Job.id == job_id).first()
        if job:
            job.status = status
            if message:
                job.status_message = message
            if progress is not None:
                job.progress_percent = progress
            for key, value in extra_fields.items():
                if hasattr(job, key):
                    setattr(job, key, value)
            db.commit()
    finally:
        db.close()


@celery_app.task(bind=True, max_retries=3)
def scan_repository_task(self, job_id: str, user_id: str):
    """
    Main scanning task:
    1. Clone repository
    2. Run secret scan
    3. Store results
    4. Clean up local files
    """
    storage = StorageClient()
    temp_dir = None
    
    try:
        # Get job details
        db = get_db_session(os.getenv('DATABASE_URL', 'sqlite:///deployguard.db'))
        job = db.query(Job).filter(Job.id == job_id).first()
        
        if not job:
            raise ValueError(f"Job {job_id} not found")
        
        # Update status
        update_job_status(job_id, JobStatus.CLONING, "Cloning repository...", 10,
                         started_at=datetime.utcnow())
        
        # Get credentials
        credentials = {}
        if job.source_credentials_id:
            credentials = CredentialService.get_credentials(
                job.source_credentials_id, user_id
            )
        
        # Create temp directory
        temp_dir = tempfile.mkdtemp(prefix=f"deployguard_{job_id}_")
        repo_path = os.path.join(temp_dir, "repo")
        
        # Build clone URL with credentials
        clone_url = job.source_url
        if credentials.get('token'):
            # Inject token into URL
            if '://' in clone_url:
                protocol, rest = clone_url.split('://', 1)
                clone_url = f"{protocol}://{credentials['token']}@{rest}"
        
        # Clone repository
        logger.info(f"Cloning repository for job {job_id}")
        result = subprocess.run(
            ['git', 'clone', '--mirror', clone_url, repo_path],
            capture_output=True, text=True, timeout=1800  # 30 min timeout
        )
        
        if result.returncode != 0:
            raise Exception(f"Git clone failed: {result.stderr}")
        
        # Get repo stats
        os.chdir(repo_path)
        branch_result = subprocess.run(
            ['git', 'branch', '-a'], capture_output=True, text=True
        )
        total_branches = len([b for b in branch_result.stdout.split('\n') if b.strip()])
        
        commit_result = subprocess.run(
            ['git', 'rev-list', '--all', '--count'], capture_output=True, text=True
        )
        total_commits = int(commit_result.stdout.strip()) if commit_result.stdout.strip() else 0
        
        update_job_status(job_id, JobStatus.SCANNING, "Scanning for secrets...", 30,
                         total_branches=total_branches, total_commits=total_commits)
        
        # Import and run scanner
        from deployguard.core.scanner import SecretScanner
        
        scanner = SecretScanner()
        scan_results = scanner.scan_repository(repo_path, include_history=True)
        
        update_job_status(job_id, JobStatus.SCANNING, "Processing scan results...", 70)
        
        # Store secrets found
        secrets_added = 0
        seen_hashes = set()
        
        for finding in scan_results.get('findings', []):
            # Create hash for deduplication
            secret_hash = hashlib.sha256(
                f"{finding.get('secret', '')}:{finding.get('file', '')}".encode()
            ).hexdigest()
            
            if secret_hash in seen_hashes:
                # Update occurrence count for existing secret
                existing = db.query(SecretFound).filter(
                    SecretFound.job_id == job_id,
                    SecretFound.secret_value_hash == secret_hash
                ).first()
                if existing:
                    existing.occurrence_count += 1
                continue
            
            seen_hashes.add(secret_hash)
            
            # Determine secret type
            secret_type = SecretType.OTHER
            pattern = finding.get('pattern', '').lower()
            if 'password' in pattern:
                secret_type = SecretType.PASSWORD
            elif 'api' in pattern or 'key' in pattern:
                secret_type = SecretType.API_KEY
            elif 'token' in pattern:
                secret_type = SecretType.TOKEN
            elif 'private' in pattern:
                secret_type = SecretType.PRIVATE_KEY
            elif 'connection' in pattern:
                secret_type = SecretType.CONNECTION_STRING
            
            # Create preview (first 3 and last 3 chars)
            secret_value = finding.get('secret', '')
            if len(secret_value) > 10:
                preview = f"{secret_value[:3]}...{secret_value[-3:]}"
            else:
                preview = "***"
            
            secret = SecretFound(
                job_id=job_id,
                secret_type=secret_type,
                secret_name=finding.get('variable_name'),
                secret_value_preview=preview,
                secret_value_hash=secret_hash,
                file_path=finding.get('file', ''),
                line_number=finding.get('line'),
                commit_hash=finding.get('commit'),
                pattern_matched=finding.get('pattern'),
                confidence=finding.get('confidence', 100),
                is_false_positive=finding.get('is_false_positive', False),
                context_before=finding.get('context_before'),
                context_after=finding.get('context_after'),
                selected_for_cleaning=True  # Default to clean
            )
            db.add(secret)
            secrets_added += 1
        
        db.commit()
        
        # Upload repo to object storage for later cleaning
        update_job_status(job_id, JobStatus.SCANNING, "Uploading to storage...", 85)
        
        s3_repo_path = f"repos/{job_id}/source"
        storage.upload_directory(repo_path, s3_repo_path)
        
        # Generate and upload report
        report_path = os.path.join(temp_dir, "scan_report.json")
        import json
        with open(report_path, 'w') as f:
            json.dump(scan_results, f, indent=2, default=str)
        
        s3_report_path = f"reports/{job_id}/scan_report.json"
        storage.upload_file(report_path, s3_report_path)
        
        # Update job as complete
        update_job_status(
            job_id, JobStatus.AWAITING_SELECTION, 
            f"Scan complete. Found {secrets_added} unique secrets.",
            100,
            total_secrets_found=secrets_added,
            storage_repo_path=s3_repo_path,
            storage_report_path=s3_report_path,
            scan_completed_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=7)  # Auto-delete after 7 days
        )
        
        logger.info(f"Scan completed for job {job_id}: {secrets_added} secrets found")
        
        return {"job_id": job_id, "secrets_found": secrets_added}
        
    except Exception as e:
        logger.error(f"Scan failed for job {job_id}: {str(e)}")
        update_job_status(job_id, JobStatus.FAILED, f"Scan failed: {str(e)}")
        raise
        
    finally:
        # Clean up temp directory
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
        try:
            db.close()
        except:
            pass


@celery_app.task(bind=True, max_retries=3)
def clean_repository_task(self, job_id: str, user_id: str, secret_ids: List[str]):
    """
    Clean repository task:
    1. Download repo from storage
    2. Generate replacement file for selected secrets
    3. Run git-filter-repo
    4. Upload cleaned repo
    5. Clean up
    """
    storage = StorageClient()
    temp_dir = None
    
    try:
        db = get_db_session(os.getenv('DATABASE_URL', 'sqlite:///deployguard.db'))
        job = db.query(Job).filter(Job.id == job_id).first()
        
        if not job:
            raise ValueError(f"Job {job_id} not found")
        
        if not job.storage_repo_path:
            raise ValueError("No repository stored for this job")
        
        update_job_status(job_id, JobStatus.CLEANING, "Downloading repository...", 10)
        
        # Create temp directory
        temp_dir = tempfile.mkdtemp(prefix=f"deployguard_clean_{job_id}_")
        repo_path = os.path.join(temp_dir, "repo")
        os.makedirs(repo_path)
        
        # Download repo from storage
        storage.download_directory(job.storage_repo_path, repo_path)
        
        update_job_status(job_id, JobStatus.CLEANING, "Preparing cleanup...", 30)
        
        # Get selected secrets
        secrets = db.query(SecretFound).filter(
            SecretFound.id.in_(secret_ids),
            SecretFound.job_id == job_id
        ).all()
        
        if not secrets:
            raise ValueError("No secrets selected for cleaning")
        
        # Update selection in database
        db.query(SecretFound).filter(SecretFound.job_id == job_id).update(
            {SecretFound.selected_for_cleaning: False}
        )
        db.query(SecretFound).filter(SecretFound.id.in_(secret_ids)).update(
            {SecretFound.selected_for_cleaning: True}
        )
        db.commit()
        
        # Create replacements file for git-filter-repo
        replacements_file = os.path.join(temp_dir, "replacements.txt")
        with open(replacements_file, 'w') as f:
            for secret in secrets:
                # Get actual secret value from scan results
                # We need to look this up from the original scan
                # For now, use a placeholder approach
                f.write(f"{secret.secret_value_preview}==>[REDACTED]\n")
        
        update_job_status(job_id, JobStatus.CLEANING, "Cleaning git history...", 50)
        
        # Run git-filter-repo
        os.chdir(repo_path)
        result = subprocess.run(
            ['git', 'filter-repo', '--replace-text', replacements_file, '--force'],
            capture_output=True, text=True, timeout=3600
        )
        
        if result.returncode != 0:
            logger.warning(f"git-filter-repo warnings: {result.stderr}")
        
        update_job_status(job_id, JobStatus.CLEANING, "Creating archive...", 75)
        
        # Create zip archive of cleaned repo
        archive_path = os.path.join(temp_dir, "cleaned_repo.zip")
        shutil.make_archive(
            archive_path.replace('.zip', ''),
            'zip',
            repo_path
        )
        
        update_job_status(job_id, JobStatus.UPLOADING, "Uploading cleaned repository...", 85)
        
        # Upload cleaned archive
        s3_cleaned_path = f"cleaned/{job_id}/cleaned_repo.zip"
        storage.upload_file(archive_path, s3_cleaned_path)
        
        # Delete the source repo from storage to save space
        storage.delete_prefix(job.storage_repo_path)
        
        # Update job
        update_job_status(
            job_id, JobStatus.CLEAN_COMPLETE,
            f"Cleanup complete. {len(secrets)} secrets removed from history.",
            100,
            secrets_selected_for_cleaning=len(secrets),
            storage_cleaned_path=s3_cleaned_path,
            storage_repo_path=None,  # Deleted
            clean_completed_at=datetime.utcnow()
        )
        
        logger.info(f"Cleanup completed for job {job_id}")
        
        return {"job_id": job_id, "secrets_cleaned": len(secrets)}
        
    except Exception as e:
        logger.error(f"Cleanup failed for job {job_id}: {str(e)}")
        update_job_status(job_id, JobStatus.FAILED, f"Cleanup failed: {str(e)}")
        raise
        
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
        try:
            db.close()
        except:
            pass


@celery_app.task(bind=True, max_retries=3)
def push_repository_task(self, job_id: str, user_id: str, target_url: str,
                         target_credentials_id: str = None, force_push: bool = True,
                         push_all_branches: bool = True):
    """
    Push cleaned repository to target:
    1. Download cleaned repo
    2. Configure remotes
    3. Push to target
    4. Clean up
    """
    storage = StorageClient()
    temp_dir = None
    
    try:
        db = get_db_session(os.getenv('DATABASE_URL', 'sqlite:///deployguard.db'))
        job = db.query(Job).filter(Job.id == job_id).first()
        
        if not job:
            raise ValueError(f"Job {job_id} not found")
        
        if not job.storage_cleaned_path:
            raise ValueError("No cleaned repository available")
        
        update_job_status(job_id, JobStatus.PUSHING, "Downloading cleaned repository...", 10)
        
        # Create temp directory
        temp_dir = tempfile.mkdtemp(prefix=f"deployguard_push_{job_id}_")
        archive_path = os.path.join(temp_dir, "cleaned_repo.zip")
        repo_path = os.path.join(temp_dir, "repo")
        
        # Download archive
        storage.client.download_file(storage.bucket, job.storage_cleaned_path, archive_path)
        
        # Extract
        shutil.unpack_archive(archive_path, repo_path)
        
        update_job_status(job_id, JobStatus.PUSHING, "Configuring target...", 30)
        
        # Get credentials
        credentials = {}
        if target_credentials_id:
            credentials = CredentialService.get_credentials(target_credentials_id, user_id)
        
        # Build target URL with credentials
        push_url = target_url
        if credentials.get('token'):
            if '://' in push_url:
                protocol, rest = push_url.split('://', 1)
                push_url = f"{protocol}://{credentials['token']}@{rest}"
        
        os.chdir(repo_path)
        
        # Add target remote
        subprocess.run(['git', 'remote', 'add', 'target', push_url], 
                      capture_output=True, check=False)
        subprocess.run(['git', 'remote', 'set-url', 'target', push_url],
                      capture_output=True, check=False)
        
        update_job_status(job_id, JobStatus.PUSHING, "Pushing to target...", 50)
        
        # Push
        push_cmd = ['git', 'push', 'target']
        if push_all_branches:
            push_cmd.append('--all')
        if force_push:
            push_cmd.append('--force')
        
        result = subprocess.run(push_cmd, capture_output=True, text=True, timeout=1800)
        
        if result.returncode != 0:
            raise Exception(f"Push failed: {result.stderr}")
        
        # Push tags
        subprocess.run(['git', 'push', 'target', '--tags'] + 
                      (['--force'] if force_push else []),
                      capture_output=True, timeout=600)
        
        update_job_status(
            job_id, JobStatus.COMPLETED,
            "Repository pushed successfully.",
            100,
            target_url=target_url,
            completed_at=datetime.utcnow()
        )
        
        # Clean up storage after successful push
        storage.delete_prefix(f"cleaned/{job_id}")
        storage.delete_prefix(f"reports/{job_id}")
        
        logger.info(f"Push completed for job {job_id}")
        
        return {"job_id": job_id, "target_url": target_url}
        
    except Exception as e:
        logger.error(f"Push failed for job {job_id}: {str(e)}")
        update_job_status(job_id, JobStatus.FAILED, f"Push failed: {str(e)}")
        raise
        
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
        try:
            db.close()
        except:
            pass


@celery_app.task
def cleanup_expired_jobs():
    """Periodic task to clean up expired jobs and storage"""
    db = get_db_session(os.getenv('DATABASE_URL', 'sqlite:///deployguard.db'))
    storage = StorageClient()
    
    try:
        expired_jobs = db.query(Job).filter(
            Job.expires_at < datetime.utcnow(),
            Job.status != JobStatus.COMPLETED
        ).all()
        
        for job in expired_jobs:
            logger.info(f"Cleaning up expired job {job.id}")
            
            # Delete storage
            if job.storage_repo_path:
                storage.delete_prefix(job.storage_repo_path)
            if job.storage_cleaned_path:
                storage.delete_prefix(job.storage_cleaned_path)
            if job.storage_report_path:
                storage.delete_prefix(os.path.dirname(job.storage_report_path))
            
            # Update job
            job.status = JobStatus.CANCELLED
            job.status_message = "Job expired and was automatically cleaned up"
        
        db.commit()
        
        return {"expired_jobs_cleaned": len(expired_jobs)}
        
    finally:
        db.close()


# Celery Beat schedule for periodic tasks
celery_app.conf.beat_schedule = {
    'cleanup-expired-jobs': {
        'task': 'deployguard.api.v2.tasks.cleanup_expired_jobs',
        'schedule': 3600.0,  # Every hour
    },
}
