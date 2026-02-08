"""
Application Layer - Use Cases

Use cases orchestrate the flow of data to and from entities,
and direct those entities to use their domain logic to achieve
the goals of the use case.
"""

from typing import Optional
from datetime import datetime
import logging

from .ports import UnitOfWork, StorageService, GitService, ScannerService, CleanerService
from .dtos import (
    CreateJobRequest, SelectSecretsRequest, StartCleaningRequest,
    PushRepositoryRequest, CancelJobRequest, GetJobRequest, ListJobsRequest,
    JobDTO, JobListDTO, SecretDTO, Result, CreateJobResult, ScanResult
)
from ..domain.entities import Job, SecretFinding, AuditEntry
from ..domain.exceptions import (
    JobNotFoundError, InvalidJobStateError, SecretsNotSelectedError,
    JobExpiredError, RepositoryAccessError
)


logger = logging.getLogger(__name__)


class CreateScanJobUseCase:
    """
    Use case for creating a new scan job and initiating the scan.
    
    Flow:
    1. Create Job entity
    2. Save Job with events to outbox (atomic)
    3. Create storage workspace
    4. Clone repository
    5. Start scanning
    6. Save results
    """
    
    def __init__(
        self,
        uow: UnitOfWork,
        storage: StorageService,
        git: GitService,
        scanner: ScannerService,
    ):
        self.uow = uow
        self.storage = storage
        self.git = git
        self.scanner = scanner
    
    async def execute(self, request: CreateJobRequest) -> Result:
        """Execute the use case."""
        try:
            # Create the job entity
            job = Job.create(
                user_id=request.user_id,
                source_platform=request.source_platform,
                source_url=request.source_url,
                source_branch=request.source_branch,
                target_platform=request.target_platform,
                target_url=request.target_url,
            )
            
            # Save job with events (atomic transaction)
            async with self.uow:
                await self.uow.jobs.save(job)
                
                # Save events to outbox for reliable delivery
                events = job.clear_events()
                await self.uow.outbox.save_all(events)
                
                # Create audit entry
                audit = AuditEntry.create(
                    job_id=job.id,
                    user_id=request.user_id,
                    action="job_created",
                    details={
                        "source_platform": request.source_platform,
                        "source_url": request.source_url,
                    },
                )
                await self.uow.audits.save(audit)
                
                await self.uow.commit()
            
            logger.info(f"Created job {job.id} for user {request.user_id}")
            
            # Return immediately - scanning will be done by Celery task
            # or can continue synchronously based on execution mode
            return Result.success(
                data=CreateJobResult(
                    job=JobDTO.from_entity(job),
                    task_id=None,  # Will be set by route if async
                ),
                message="Job created successfully",
            )
            
        except Exception as e:
            logger.error(f"Failed to create job: {e}")
            return Result.failure(str(e))


class ExecuteScanUseCase:
    """
    Use case for executing the actual scan (called by Celery worker or sync).
    
    This is separated from CreateScanJobUseCase to allow
    async execution via Celery.
    """
    
    def __init__(
        self,
        uow: UnitOfWork,
        storage: StorageService,
        git: GitService,
        scanner: ScannerService,
    ):
        self.uow = uow
        self.storage = storage
        self.git = git
        self.scanner = scanner
    
    async def execute(
        self,
        job_id: str,
        source_token: Optional[str] = None,
        progress_callback: Optional[callable] = None,
    ) -> Result:
        """Execute the scan."""
        try:
            # Get the job
            job = await self.uow.jobs.get_by_id(job_id)
            if not job:
                return Result.not_found(f"Job {job_id} not found")
            
            start_time = datetime.utcnow()
            
            # Start scanning
            job.start_scanning()
            
            async with self.uow:
                await self.uow.jobs.save(job)
                await self.uow.outbox.save_all(job.clear_events())
                await self.uow.commit()
            
            # Create workspace
            workspace_path = await self.storage.create_workspace(job_id)
            job.set_storage_path(workspace_path)
            
            # Clone repository
            if progress_callback:
                progress_callback(10, "Cloning repository...")
            
            credentials = {"token": source_token} if source_token else None
            await self.git.clone(
                url=job.source_url,
                target_path=workspace_path,
                branch=job.source_branch,
                credentials=credentials,
            )
            
            if progress_callback:
                progress_callback(30, "Scanning for secrets...")
            
            # Scan for secrets
            findings = await self.scanner.scan(
                repo_path=workspace_path,
                progress_callback=lambda p, m: progress_callback(30 + int(p * 0.6), m) if progress_callback else None,
            )
            
            # Convert findings to domain entities
            secrets = [
                SecretFinding.create(
                    job_id=job_id,
                    file_path=f["file_path"],
                    line_number=f["line_number"],
                    commit_hash=f["commit_hash"],
                    secret_value=f["secret_value"],
                    pattern_name=f["pattern_name"],
                    severity=f.get("severity", "medium"),
                    confidence=f.get("confidence", 0.8),
                    branch=f.get("branch", "main"),
                    code_context=f.get("code_context", ""),
                    author=f.get("author", ""),
                    commit_date=f.get("commit_date"),
                )
                for f in findings
            ]
            
            # Complete scan
            scan_duration = (datetime.utcnow() - start_time).total_seconds()
            job.complete_scan(
                secrets=secrets,
                total_commits=len(set(f["commit_hash"] for f in findings)),
                total_branches=1,  # TODO: multi-branch support
                scan_duration=scan_duration,
            )
            
            # Save final state
            async with self.uow:
                await self.uow.jobs.save(job)
                await self.uow.secrets.save_all(secrets)
                await self.uow.outbox.save_all(job.clear_events())
                
                # Audit entry
                audit = AuditEntry.create(
                    job_id=job_id,
                    user_id=job.user_id,
                    action="scan_completed",
                    details={
                        "secrets_found": len(secrets),
                        "duration_seconds": scan_duration,
                    },
                )
                await self.uow.audits.save(audit)
                
                await self.uow.commit()
            
            if progress_callback:
                progress_callback(100, "Scan completed")
            
            logger.info(f"Scan completed for job {job_id}: {len(secrets)} secrets found")
            
            return Result.success(
                data=ScanResult(
                    job=JobDTO.from_entity(job, include_secrets=True),
                    scan_duration_seconds=scan_duration,
                ),
                message=f"Found {len(secrets)} secrets",
            )
            
        except Exception as e:
            logger.error(f"Scan failed for job {job_id}: {e}")
            
            # Mark job as failed
            try:
                job = await self.uow.jobs.get_by_id(job_id)
                if job:
                    job.fail("SCAN_ERROR", str(e))
                    async with self.uow:
                        await self.uow.jobs.save(job)
                        await self.uow.outbox.save_all(job.clear_events())
                        await self.uow.commit()
            except Exception:
                pass
            
            return Result.failure(str(e))


class SelectSecretsUseCase:
    """
    Use case for selecting secrets to clean.
    
    User reviews found secrets and selects which to clean,
    marking false positives as needed.
    """
    
    def __init__(self, uow: UnitOfWork):
        self.uow = uow
    
    async def execute(self, request: SelectSecretsRequest) -> Result:
        """Execute the use case."""
        try:
            job = await self.uow.jobs.get_by_id(request.job_id)
            if not job:
                return Result.not_found(f"Job {request.job_id} not found")
            
            if job.user_id != request.user_id:
                return Result.forbidden("Access denied")
            
            # Load secrets
            job.secrets = await self.uow.secrets.get_by_job(request.job_id)
            
            # Apply selection
            job.select_secrets(
                selected_ids=request.selected_secret_ids,
                false_positive_ids=request.false_positive_ids,
            )
            
            # Save changes
            async with self.uow:
                await self.uow.jobs.save(job)
                await self.uow.secrets.update_selection(
                    job_id=request.job_id,
                    selected_ids=request.selected_secret_ids,
                    false_positive_ids=request.false_positive_ids,
                )
                await self.uow.outbox.save_all(job.clear_events())
                
                # Audit entry
                audit = AuditEntry.create(
                    job_id=request.job_id,
                    user_id=request.user_id,
                    action="secrets_selected",
                    details={
                        "selected_count": len(request.selected_secret_ids),
                        "false_positives_count": len(request.false_positive_ids),
                    },
                )
                await self.uow.audits.save(audit)
                
                await self.uow.commit()
            
            logger.info(
                f"Secrets selected for job {request.job_id}: "
                f"{len(request.selected_secret_ids)} selected, "
                f"{len(request.false_positive_ids)} false positives"
            )
            
            return Result.success(
                data=JobDTO.from_entity(job),
                message="Secrets selection saved",
            )
            
        except InvalidJobStateError as e:
            return Result.conflict(str(e))
        except Exception as e:
            logger.error(f"Failed to select secrets: {e}")
            return Result.failure(str(e))


class StartCleaningUseCase:
    """
    Use case for starting the cleaning process.
    
    Initiates the history cleaning operation for selected secrets.
    """
    
    def __init__(self, uow: UnitOfWork, cleaner: CleanerService):
        self.uow = uow
        self.cleaner = cleaner
    
    async def execute(self, request: StartCleaningRequest) -> Result:
        """Execute the use case."""
        try:
            job = await self.uow.jobs.get_by_id(request.job_id)
            if not job:
                return Result.not_found(f"Job {request.job_id} not found")
            
            if job.user_id != request.user_id:
                return Result.forbidden("Access denied")
            
            # Load secrets
            job.secrets = await self.uow.secrets.get_by_job(request.job_id)
            
            # Start cleaning
            job.start_cleaning()
            
            async with self.uow:
                await self.uow.jobs.save(job)
                await self.uow.outbox.save_all(job.clear_events())
                
                audit = AuditEntry.create(
                    job_id=request.job_id,
                    user_id=request.user_id,
                    action="cleaning_started",
                    details={"secrets_to_clean": len(job.selected_secrets)},
                )
                await self.uow.audits.save(audit)
                
                await self.uow.commit()
            
            # Return immediately - cleaning will be done by Celery
            return Result.success(
                data=JobDTO.from_entity(job),
                message="Cleaning started",
            )
            
        except InvalidJobStateError as e:
            return Result.conflict(str(e))
        except SecretsNotSelectedError as e:
            return Result.validation_error([str(e)])
        except Exception as e:
            logger.error(f"Failed to start cleaning: {e}")
            return Result.failure(str(e))


class ExecuteCleaningUseCase:
    """
    Use case for executing the actual cleaning (called by Celery worker).
    """
    
    def __init__(self, uow: UnitOfWork, cleaner: CleanerService):
        self.uow = uow
        self.cleaner = cleaner
    
    async def execute(
        self,
        job_id: str,
        progress_callback: Optional[callable] = None,
    ) -> Result:
        """Execute the cleaning."""
        try:
            job = await self.uow.jobs.get_by_id(job_id)
            if not job:
                return Result.not_found(f"Job {job_id} not found")
            
            job.secrets = await self.uow.secrets.get_by_job(job_id)
            
            start_time = datetime.utcnow()
            
            # Get secrets to remove
            secrets_to_remove = [
                s.secret_hash for s in job.selected_secrets
            ]
            
            if progress_callback:
                progress_callback(10, "Starting history cleanup...")
            
            # Perform cleaning
            result = await self.cleaner.clean(
                repo_path=job.storage_path,
                secrets_to_remove=secrets_to_remove,
                progress_callback=progress_callback,
            )
            
            clean_duration = (datetime.utcnow() - start_time).total_seconds()
            
            # Complete cleaning
            job.complete_cleaning(
                secrets_cleaned=result["secrets_removed"],
                commits_rewritten=result["commits_rewritten"],
                clean_duration=clean_duration,
            )
            
            async with self.uow:
                await self.uow.jobs.save(job)
                await self.uow.outbox.save_all(job.clear_events())
                
                audit = AuditEntry.create(
                    job_id=job_id,
                    user_id=job.user_id,
                    action="cleaning_completed",
                    details={
                        "secrets_cleaned": result["secrets_removed"],
                        "commits_rewritten": result["commits_rewritten"],
                        "duration_seconds": clean_duration,
                    },
                )
                await self.uow.audits.save(audit)
                
                await self.uow.commit()
            
            if progress_callback:
                progress_callback(100, "Cleaning completed")
            
            logger.info(f"Cleaning completed for job {job_id}")
            
            return Result.success(
                data=JobDTO.from_entity(job),
                message="Cleaning completed",
            )
            
        except Exception as e:
            logger.error(f"Cleaning failed for job {job_id}: {e}")
            
            try:
                job = await self.uow.jobs.get_by_id(job_id)
                if job:
                    job.fail("CLEAN_ERROR", str(e))
                    async with self.uow:
                        await self.uow.jobs.save(job)
                        await self.uow.outbox.save_all(job.clear_events())
                        await self.uow.commit()
            except Exception:
                pass
            
            return Result.failure(str(e))


class PushRepositoryUseCase:
    """
    Use case for pushing cleaned repository to target.
    """
    
    def __init__(self, uow: UnitOfWork, git: GitService):
        self.uow = uow
        self.git = git
    
    async def execute(
        self,
        request: PushRepositoryRequest,
        progress_callback: Optional[callable] = None,
    ) -> Result:
        """Execute the push."""
        try:
            job = await self.uow.jobs.get_by_id(request.job_id)
            if not job:
                return Result.not_found(f"Job {request.job_id} not found")
            
            if job.user_id != request.user_id:
                return Result.forbidden("Access denied")
            
            # Update target if provided
            if request.target_url:
                job.target_url = request.target_url
            if request.target_platform:
                job.target_platform = request.target_platform
            
            # Start pushing
            job.start_pushing(force_push=request.force_push)
            
            async with self.uow:
                await self.uow.jobs.save(job)
                await self.uow.outbox.save_all(job.clear_events())
                await self.uow.commit()
            
            if progress_callback:
                progress_callback(10, "Pushing to target repository...")
            
            # Perform push
            credentials = {"token": request.target_token} if request.target_token else None
            result = await self.git.push(
                repo_path=job.storage_path,
                remote_url=job.target_url,
                force=request.force_push,
                credentials=credentials,
            )
            
            # Complete push
            job.complete_push(
                branches_pushed=result["branches_pushed"],
                tags_pushed=result["tags_pushed"],
            )
            
            async with self.uow:
                await self.uow.jobs.save(job)
                await self.uow.outbox.save_all(job.clear_events())
                
                audit = AuditEntry.create(
                    job_id=request.job_id,
                    user_id=request.user_id,
                    action="push_completed",
                    details={
                        "target_url": job.target_url,
                        "branches_pushed": result["branches_pushed"],
                        "tags_pushed": result["tags_pushed"],
                    },
                )
                await self.uow.audits.save(audit)
                
                await self.uow.commit()
            
            if progress_callback:
                progress_callback(100, "Push completed")
            
            logger.info(f"Push completed for job {request.job_id}")
            
            return Result.success(
                data=JobDTO.from_entity(job),
                message="Repository pushed successfully",
            )
            
        except InvalidJobStateError as e:
            return Result.conflict(str(e))
        except Exception as e:
            logger.error(f"Push failed: {e}")
            
            try:
                job = await self.uow.jobs.get_by_id(request.job_id)
                if job:
                    job.fail("PUSH_ERROR", str(e))
                    async with self.uow:
                        await self.uow.jobs.save(job)
                        await self.uow.outbox.save_all(job.clear_events())
                        await self.uow.commit()
            except Exception:
                pass
            
            return Result.failure(str(e))


class GetJobUseCase:
    """Use case for getting a single job."""
    
    def __init__(self, uow: UnitOfWork):
        self.uow = uow
    
    async def execute(self, request: GetJobRequest) -> Result:
        """Execute the use case."""
        job = await self.uow.jobs.get_by_id(request.job_id)
        if not job:
            return Result.not_found(f"Job {request.job_id} not found")
        
        if job.user_id != request.user_id:
            return Result.forbidden("Access denied")
        
        if request.include_secrets:
            job.secrets = await self.uow.secrets.get_by_job(request.job_id)
        
        return Result.success(
            data=JobDTO.from_entity(job, include_secrets=request.include_secrets)
        )


class ListJobsUseCase:
    """Use case for listing jobs for a user."""
    
    def __init__(self, uow: UnitOfWork):
        self.uow = uow
    
    async def execute(self, request: ListJobsRequest) -> Result:
        """Execute the use case."""
        jobs = await self.uow.jobs.get_by_user(
            user_id=request.user_id,
            skip=request.skip,
            limit=request.limit,
        )
        
        total = await self.uow.jobs.count_by_user(request.user_id)
        
        return Result.success(
            data=JobListDTO(
                items=[JobDTO.from_entity(j) for j in jobs],
                total=total,
                skip=request.skip,
                limit=request.limit,
                has_more=(request.skip + len(jobs)) < total,
            )
        )


class CancelJobUseCase:
    """Use case for cancelling a job."""
    
    def __init__(self, uow: UnitOfWork, storage: StorageService):
        self.uow = uow
        self.storage = storage
    
    async def execute(self, request: CancelJobRequest) -> Result:
        """Execute the use case."""
        try:
            job = await self.uow.jobs.get_by_id(request.job_id)
            if not job:
                return Result.not_found(f"Job {request.job_id} not found")
            
            if job.user_id != request.user_id:
                return Result.forbidden("Access denied")
            
            job.cancel(reason=request.reason)
            
            async with self.uow:
                await self.uow.jobs.save(job)
                await self.uow.outbox.save_all(job.clear_events())
                
                audit = AuditEntry.create(
                    job_id=request.job_id,
                    user_id=request.user_id,
                    action="job_cancelled",
                    details={"reason": request.reason},
                )
                await self.uow.audits.save(audit)
                
                await self.uow.commit()
            
            # Cleanup storage
            try:
                await self.storage.delete_workspace(request.job_id)
            except Exception:
                pass  # Best effort cleanup
            
            logger.info(f"Job {request.job_id} cancelled")
            
            return Result.success(
                data=JobDTO.from_entity(job),
                message="Job cancelled",
            )
            
        except InvalidJobStateError as e:
            return Result.conflict(str(e))
        except Exception as e:
            logger.error(f"Failed to cancel job: {e}")
            return Result.failure(str(e))
