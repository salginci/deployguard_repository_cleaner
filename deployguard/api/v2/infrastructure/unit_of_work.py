"""
Infrastructure Layer - Unit of Work Implementation

Manages database transactions and coordinates repositories.
"""

from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from ..application.ports import (
    UnitOfWork, JobRepository, SecretRepository, AuditRepository, OutboxRepository
)
from .repositories import (
    SQLAlchemyJobRepository, SQLAlchemySecretRepository,
    SQLAlchemyAuditRepository, SQLAlchemyOutboxRepository
)


class SQLAlchemyUnitOfWork(UnitOfWork):
    """
    SQLAlchemy implementation of Unit of Work pattern.
    
    Manages database sessions and transactions, ensuring that
    all operations within a use case are committed or rolled
    back together.
    
    Usage:
        async with uow:
            await uow.jobs.save(job)
            await uow.outbox.save_all(events)
            await uow.commit()
    """
    
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory
        self._session: Optional[AsyncSession] = None
        
        # Lazy-initialized repositories
        self._jobs: Optional[JobRepository] = None
        self._secrets: Optional[SecretRepository] = None
        self._audits: Optional[AuditRepository] = None
        self._outbox: Optional[OutboxRepository] = None
    
    @property
    def jobs(self) -> JobRepository:
        """Get the job repository."""
        if self._jobs is None:
            self._jobs = SQLAlchemyJobRepository(self._session)
        return self._jobs
    
    @property
    def secrets(self) -> SecretRepository:
        """Get the secret repository."""
        if self._secrets is None:
            self._secrets = SQLAlchemySecretRepository(self._session)
        return self._secrets
    
    @property
    def audits(self) -> AuditRepository:
        """Get the audit repository."""
        if self._audits is None:
            self._audits = SQLAlchemyAuditRepository(self._session)
        return self._audits
    
    @property
    def outbox(self) -> OutboxRepository:
        """Get the outbox repository."""
        if self._outbox is None:
            self._outbox = SQLAlchemyOutboxRepository(self._session)
        return self._outbox
    
    async def begin(self) -> None:
        """Begin a transaction."""
        if self._session is None:
            self._session = self._session_factory()
    
    async def commit(self) -> None:
        """Commit the transaction."""
        if self._session:
            await self._session.commit()
    
    async def rollback(self) -> None:
        """Rollback the transaction."""
        if self._session:
            await self._session.rollback()
    
    async def __aenter__(self) -> 'SQLAlchemyUnitOfWork':
        """Enter async context manager."""
        await self.begin()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit async context manager, commit or rollback."""
        if exc_type is not None:
            await self.rollback()
        
        # Close session
        if self._session:
            await self._session.close()
            self._session = None
        
        # Reset repositories
        self._jobs = None
        self._secrets = None
        self._audits = None
        self._outbox = None


def create_unit_of_work_factory(database_url: str) -> async_sessionmaker[AsyncSession]:
    """
    Create a session factory for the Unit of Work.
    
    Args:
        database_url: PostgreSQL async connection string
                     (e.g., postgresql+asyncpg://user:pass@host/db)
    
    Returns:
        Async session factory
    """
    engine = create_async_engine(
        database_url,
        echo=False,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )
    
    return async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
