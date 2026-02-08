"""
Dependency Injection Container

Provides dependency injection for the clean architecture components.
This follows the Composition Root pattern.
"""

from typing import Optional
from functools import lru_cache
import os

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .application.ports import UnitOfWork
from .application.use_cases import (
    CreateScanJobUseCase,
    ExecuteScanUseCase,
    SelectSecretsUseCase,
    StartCleaningUseCase,
    ExecuteCleaningUseCase,
    PushRepositoryUseCase,
    GetJobUseCase,
    ListJobsUseCase,
    CancelJobUseCase,
)
from .infrastructure.unit_of_work import SQLAlchemyUnitOfWork, create_unit_of_work_factory
from .infrastructure.services import (
    LocalStorageService,
    GitCommandService,
    SecretScannerService,
    HistoryCleanerService,
)
from .infrastructure.outbox_processor import RabbitMQEventPublisher


class Container:
    """
    Dependency Injection Container.
    
    Manages the lifecycle of dependencies and provides
    factory methods for use cases.
    
    Usage:
        container = Container.from_env()
        create_job_uc = container.create_scan_job_use_case()
        result = await create_job_uc.execute(request)
    """
    
    def __init__(
        self,
        database_url: str,
        rabbitmq_url: str,
        storage_path: str = "/tmp/deployguard",
        patterns_path: Optional[str] = None,
    ):
        self.database_url = database_url
        self.rabbitmq_url = rabbitmq_url
        self.storage_path = storage_path
        self.patterns_path = patterns_path
        
        # Lazy-initialized components
        self._session_factory: Optional[async_sessionmaker[AsyncSession]] = None
        self._storage_service: Optional[LocalStorageService] = None
        self._git_service: Optional[GitCommandService] = None
        self._scanner_service: Optional[SecretScannerService] = None
        self._cleaner_service: Optional[HistoryCleanerService] = None
        self._event_publisher: Optional[RabbitMQEventPublisher] = None
    
    @classmethod
    def from_env(cls) -> 'Container':
        """Create container from environment variables."""
        return cls(
            database_url=os.getenv(
                'DATABASE_URL',
                'postgresql+asyncpg://deployguard:deployguard@localhost/deployguard'
            ),
            rabbitmq_url=os.getenv(
                'RABBITMQ_URL',
                'amqp://guest:guest@localhost:5672/'
            ),
            storage_path=os.getenv('STORAGE_PATH', '/tmp/deployguard'),
            patterns_path=os.getenv('PATTERNS_PATH'),
        )
    
    # ==================== Infrastructure Components ====================
    
    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        """Get SQLAlchemy session factory."""
        if self._session_factory is None:
            self._session_factory = create_unit_of_work_factory(self.database_url)
        return self._session_factory
    
    @property
    def storage_service(self) -> LocalStorageService:
        """Get storage service."""
        if self._storage_service is None:
            self._storage_service = LocalStorageService(self.storage_path)
        return self._storage_service
    
    @property
    def git_service(self) -> GitCommandService:
        """Get git service."""
        if self._git_service is None:
            self._git_service = GitCommandService()
        return self._git_service
    
    @property
    def scanner_service(self) -> SecretScannerService:
        """Get scanner service."""
        if self._scanner_service is None:
            self._scanner_service = SecretScannerService(self.patterns_path)
        return self._scanner_service
    
    @property
    def cleaner_service(self) -> HistoryCleanerService:
        """Get cleaner service."""
        if self._cleaner_service is None:
            self._cleaner_service = HistoryCleanerService()
        return self._cleaner_service
    
    @property
    def event_publisher(self) -> RabbitMQEventPublisher:
        """Get event publisher."""
        if self._event_publisher is None:
            self._event_publisher = RabbitMQEventPublisher(self.rabbitmq_url)
        return self._event_publisher
    
    # ==================== Unit of Work ====================
    
    def unit_of_work(self) -> SQLAlchemyUnitOfWork:
        """Create a new Unit of Work instance."""
        return SQLAlchemyUnitOfWork(self.session_factory)
    
    # ==================== Use Case Factories ====================
    
    def create_scan_job_use_case(self) -> CreateScanJobUseCase:
        """Create the CreateScanJobUseCase."""
        return CreateScanJobUseCase(
            uow=self.unit_of_work(),
            storage=self.storage_service,
            git=self.git_service,
            scanner=self.scanner_service,
        )
    
    def execute_scan_use_case(self) -> ExecuteScanUseCase:
        """Create the ExecuteScanUseCase."""
        return ExecuteScanUseCase(
            uow=self.unit_of_work(),
            storage=self.storage_service,
            git=self.git_service,
            scanner=self.scanner_service,
        )
    
    def select_secrets_use_case(self) -> SelectSecretsUseCase:
        """Create the SelectSecretsUseCase."""
        return SelectSecretsUseCase(uow=self.unit_of_work())
    
    def start_cleaning_use_case(self) -> StartCleaningUseCase:
        """Create the StartCleaningUseCase."""
        return StartCleaningUseCase(
            uow=self.unit_of_work(),
            cleaner=self.cleaner_service,
        )
    
    def execute_cleaning_use_case(self) -> ExecuteCleaningUseCase:
        """Create the ExecuteCleaningUseCase."""
        return ExecuteCleaningUseCase(
            uow=self.unit_of_work(),
            cleaner=self.cleaner_service,
        )
    
    def push_repository_use_case(self) -> PushRepositoryUseCase:
        """Create the PushRepositoryUseCase."""
        return PushRepositoryUseCase(
            uow=self.unit_of_work(),
            git=self.git_service,
        )
    
    def get_job_use_case(self) -> GetJobUseCase:
        """Create the GetJobUseCase."""
        return GetJobUseCase(uow=self.unit_of_work())
    
    def list_jobs_use_case(self) -> ListJobsUseCase:
        """Create the ListJobsUseCase."""
        return ListJobsUseCase(uow=self.unit_of_work())
    
    def cancel_job_use_case(self) -> CancelJobUseCase:
        """Create the CancelJobUseCase."""
        return CancelJobUseCase(
            uow=self.unit_of_work(),
            storage=self.storage_service,
        )


# Global container instance (singleton)
_container: Optional[Container] = None


def get_container() -> Container:
    """Get the global container instance."""
    global _container
    if _container is None:
        _container = Container.from_env()
    return _container


def set_container(container: Container) -> None:
    """Set the global container instance (for testing)."""
    global _container
    _container = container
