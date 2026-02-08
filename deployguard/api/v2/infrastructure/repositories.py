"""
Infrastructure Layer - Repository Implementations

Concrete implementations of repository interfaces using SQLAlchemy.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, func
from sqlalchemy.orm import selectinload

from ..application.ports import (
    JobRepository, SecretRepository, AuditRepository, OutboxRepository
)
from ..domain.entities import Job, SecretFinding, AuditEntry
from ..domain.value_objects import JobStatus, SecretType, Severity
from ..domain.events import DomainEvent
from .db_models import JobModel, SecretModel, AuditModel, OutboxModel


class SQLAlchemyJobRepository(JobRepository):
    """SQLAlchemy implementation of JobRepository."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def save(self, job: Job) -> None:
        """Save a job (insert or update)."""
        existing = await self.session.get(JobModel, job.id)
        
        if existing:
            # Update existing
            existing.user_id = job.user_id
            existing.source_platform = job.source_platform
            existing.source_url = job.source_url
            existing.source_branch = job.source_branch
            existing.target_platform = job.target_platform
            existing.target_url = job.target_url
            existing.status = job.status.value
            existing.status_message = job.status_message
            existing.progress_percent = job.progress_percent
            existing.total_commits_scanned = job.total_commits_scanned
            existing.total_branches_scanned = job.total_branches_scanned
            existing.commits_rewritten = job.commits_rewritten
            existing.branches_pushed = job.branches_pushed
            existing.tags_pushed = job.tags_pushed
            existing.storage_path = job.storage_path
            existing.error_code = job.error_code
            existing.error_message = job.error_message
            existing.updated_at = job.updated_at
            existing.expires_at = job.expires_at
            existing.version = job.version
        else:
            # Insert new
            model = JobModel(
                id=job.id,
                user_id=job.user_id,
                source_platform=job.source_platform,
                source_url=job.source_url,
                source_branch=job.source_branch,
                target_platform=job.target_platform,
                target_url=job.target_url,
                status=job.status.value,
                status_message=job.status_message,
                progress_percent=job.progress_percent,
                total_commits_scanned=job.total_commits_scanned,
                total_branches_scanned=job.total_branches_scanned,
                commits_rewritten=job.commits_rewritten,
                branches_pushed=job.branches_pushed,
                tags_pushed=job.tags_pushed,
                storage_path=job.storage_path,
                error_code=job.error_code,
                error_message=job.error_message,
                created_at=job.created_at,
                updated_at=job.updated_at,
                expires_at=job.expires_at,
                version=job.version,
            )
            self.session.add(model)
    
    async def get_by_id(self, job_id: str) -> Optional[Job]:
        """Get a job by ID."""
        model = await self.session.get(JobModel, job_id)
        if not model:
            return None
        return self._to_entity(model)
    
    async def get_by_user(
        self,
        user_id: str,
        skip: int = 0,
        limit: int = 20,
    ) -> List[Job]:
        """Get jobs for a user."""
        stmt = (
            select(JobModel)
            .where(JobModel.user_id == user_id)
            .order_by(JobModel.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return [self._to_entity(m) for m in result.scalars().all()]
    
    async def delete(self, job_id: str) -> bool:
        """Delete a job."""
        stmt = delete(JobModel).where(JobModel.id == job_id)
        result = await self.session.execute(stmt)
        return result.rowcount > 0
    
    async def get_expired_jobs(self, before: datetime) -> List[Job]:
        """Get expired jobs."""
        stmt = (
            select(JobModel)
            .where(JobModel.expires_at < before)
            .where(JobModel.status.notin_([
                JobStatus.COMPLETED.value,
                JobStatus.FAILED.value,
                JobStatus.CANCELLED.value,
                JobStatus.EXPIRED.value,
            ]))
        )
        result = await self.session.execute(stmt)
        return [self._to_entity(m) for m in result.scalars().all()]
    
    async def count_by_user(self, user_id: str) -> int:
        """Count jobs for a user."""
        stmt = select(func.count()).select_from(JobModel).where(JobModel.user_id == user_id)
        result = await self.session.execute(stmt)
        return result.scalar() or 0
    
    def _to_entity(self, model: JobModel) -> Job:
        """Convert model to entity."""
        return Job(
            id=model.id,
            user_id=model.user_id,
            source_platform=model.source_platform,
            source_url=model.source_url,
            source_branch=model.source_branch,
            target_platform=model.target_platform,
            target_url=model.target_url,
            status=JobStatus(model.status),
            status_message=model.status_message,
            progress_percent=model.progress_percent,
            total_commits_scanned=model.total_commits_scanned,
            total_branches_scanned=model.total_branches_scanned,
            commits_rewritten=model.commits_rewritten,
            branches_pushed=model.branches_pushed,
            tags_pushed=model.tags_pushed,
            storage_path=model.storage_path,
            error_code=model.error_code,
            error_message=model.error_message,
            created_at=model.created_at,
            updated_at=model.updated_at,
            expires_at=model.expires_at,
            version=model.version,
            secrets=[],  # Loaded separately
        )


class SQLAlchemySecretRepository(SecretRepository):
    """SQLAlchemy implementation of SecretRepository."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def save_all(self, secrets: List[SecretFinding]) -> None:
        """Save multiple secrets."""
        models = [
            SecretModel(
                id=s.id,
                job_id=s.job_id,
                file_path=s.file_path,
                line_number=s.line_number,
                commit_hash=s.commit_hash,
                branch=s.branch,
                secret_type=s.secret_type.value,
                secret_hash=s.secret_hash,
                secret_preview=s.secret_preview,
                pattern_name=s.pattern_name,
                code_context=s.code_context,
                author=s.author,
                commit_date=s.commit_date,
                severity=s.severity.value,
                confidence=s.confidence,
                selected_for_cleaning=s.selected_for_cleaning,
                marked_as_false_positive=s.marked_as_false_positive,
                found_at=s.found_at,
            )
            for s in secrets
        ]
        self.session.add_all(models)
    
    async def get_by_job(self, job_id: str) -> List[SecretFinding]:
        """Get secrets for a job."""
        stmt = select(SecretModel).where(SecretModel.job_id == job_id)
        result = await self.session.execute(stmt)
        return [self._to_entity(m) for m in result.scalars().all()]
    
    async def update_selection(
        self,
        job_id: str,
        selected_ids: List[str],
        false_positive_ids: List[str],
    ) -> None:
        """Update selection state."""
        # Reset all to not selected
        stmt = (
            update(SecretModel)
            .where(SecretModel.job_id == job_id)
            .values(selected_for_cleaning=False, marked_as_false_positive=False)
        )
        await self.session.execute(stmt)
        
        # Mark selected
        if selected_ids:
            stmt = (
                update(SecretModel)
                .where(SecretModel.id.in_(selected_ids))
                .values(selected_for_cleaning=True)
            )
            await self.session.execute(stmt)
        
        # Mark false positives
        if false_positive_ids:
            stmt = (
                update(SecretModel)
                .where(SecretModel.id.in_(false_positive_ids))
                .values(marked_as_false_positive=True)
            )
            await self.session.execute(stmt)
    
    async def delete_by_job(self, job_id: str) -> int:
        """Delete secrets for a job."""
        stmt = delete(SecretModel).where(SecretModel.job_id == job_id)
        result = await self.session.execute(stmt)
        return result.rowcount
    
    def _to_entity(self, model: SecretModel) -> SecretFinding:
        """Convert model to entity."""
        return SecretFinding(
            id=model.id,
            job_id=model.job_id,
            file_path=model.file_path,
            line_number=model.line_number,
            commit_hash=model.commit_hash,
            branch=model.branch,
            secret_type=SecretType(model.secret_type),
            secret_hash=model.secret_hash,
            secret_preview=model.secret_preview,
            pattern_name=model.pattern_name,
            code_context=model.code_context,
            author=model.author,
            commit_date=model.commit_date,
            severity=Severity(model.severity),
            confidence=model.confidence,
            selected_for_cleaning=model.selected_for_cleaning,
            marked_as_false_positive=model.marked_as_false_positive,
            found_at=model.found_at,
        )


class SQLAlchemyAuditRepository(AuditRepository):
    """SQLAlchemy implementation of AuditRepository."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def save(self, entry: AuditEntry) -> None:
        """Save an audit entry."""
        model = AuditModel(
            id=entry.id,
            job_id=entry.job_id,
            user_id=entry.user_id,
            action=entry.action,
            details=entry.details,
            ip_address=entry.ip_address,
            user_agent=entry.user_agent,
            created_at=entry.created_at,
        )
        self.session.add(model)
    
    async def get_by_job(
        self,
        job_id: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """Get audit entries for a job."""
        stmt = (
            select(AuditModel)
            .where(AuditModel.job_id == job_id)
            .order_by(AuditModel.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return [self._to_entity(m) for m in result.scalars().all()]
    
    async def get_by_user(
        self,
        user_id: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """Get audit entries for a user."""
        stmt = (
            select(AuditModel)
            .where(AuditModel.user_id == user_id)
            .order_by(AuditModel.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return [self._to_entity(m) for m in result.scalars().all()]
    
    def _to_entity(self, model: AuditModel) -> AuditEntry:
        """Convert model to entity."""
        return AuditEntry(
            id=model.id,
            job_id=model.job_id,
            user_id=model.user_id,
            action=model.action,
            details=model.details,
            ip_address=model.ip_address,
            user_agent=model.user_agent,
            created_at=model.created_at,
        )


class SQLAlchemyOutboxRepository(OutboxRepository):
    """
    SQLAlchemy implementation of OutboxRepository.
    
    Implements the Outbox Pattern for reliable event publishing.
    """
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def save(self, event: DomainEvent) -> None:
        """Save an event to the outbox."""
        model = OutboxModel(
            event_id=event.event_id,
            event_type=event.event_type,
            aggregate_type=event.aggregate_type,
            aggregate_id=event.aggregate_id,
            payload=event.to_dict(),
            published=False,
            created_at=event.occurred_at,
        )
        self.session.add(model)
    
    async def save_all(self, events: List[DomainEvent]) -> None:
        """Save multiple events to the outbox."""
        models = [
            OutboxModel(
                event_id=e.event_id,
                event_type=e.event_type,
                aggregate_type=e.aggregate_type,
                aggregate_id=e.aggregate_id,
                payload=e.to_dict(),
                published=False,
                created_at=e.occurred_at,
            )
            for e in events
        ]
        self.session.add_all(models)
    
    async def get_unpublished(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get unpublished events for processing."""
        stmt = (
            select(OutboxModel)
            .where(OutboxModel.published == False)
            .order_by(OutboxModel.created_at.asc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        
        return [
            {
                'id': m.id,
                'event_id': m.event_id,
                'event_type': m.event_type,
                'aggregate_type': m.aggregate_type,
                'aggregate_id': m.aggregate_id,
                'payload': m.payload,
                'created_at': m.created_at,
                'retry_count': m.retry_count,
            }
            for m in result.scalars().all()
        ]
    
    async def mark_as_published(self, message_ids: List[str]) -> None:
        """Mark events as published."""
        stmt = (
            update(OutboxModel)
            .where(OutboxModel.id.in_(message_ids))
            .values(published=True, published_at=datetime.utcnow())
        )
        await self.session.execute(stmt)
    
    async def delete_published(self, older_than: datetime) -> int:
        """Delete old published messages."""
        stmt = (
            delete(OutboxModel)
            .where(OutboxModel.published == True)
            .where(OutboxModel.published_at < older_than)
        )
        result = await self.session.execute(stmt)
        return result.rowcount
    
    async def increment_retry(self, message_id: str, error: str) -> None:
        """Increment retry count and store last error."""
        stmt = (
            update(OutboxModel)
            .where(OutboxModel.id == message_id)
            .values(
                retry_count=OutboxModel.retry_count + 1,
                last_error=error,
            )
        )
        await self.session.execute(stmt)
