# Clean Architecture Refactoring

This document describes the clean architecture implementation for the DeployGuard API v2.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                           API Layer                                  │
│  (FastAPI routes, request/response models, HTTP concerns)           │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       Application Layer                              │
│  (Use Cases, DTOs, Ports/Interfaces)                                │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │CreateScanJob │  │SelectSecrets │  │StartCleaning │  ...         │
│  │  UseCase     │  │  UseCase     │  │  UseCase     │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Domain Layer                                 │
│  (Entities, Value Objects, Domain Events, Domain Exceptions)        │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │    Job       │  │SecretFinding │  │ AuditEntry   │              │
│  │ (Aggregate)  │  │  (Entity)    │  │  (Entity)    │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │  JobStatus   │  │ SecretType   │  │  Severity    │              │
│  │(Value Object)│  │(Value Object)│  │(Value Object)│              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Infrastructure Layer                             │
│  (Repository Implementations, Services, Database Models)            │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │SQLAlchemy    │  │ Storage      │  │  Git         │              │
│  │Repositories  │  │ Service      │  │  Service     │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐                                 │
│  │  Outbox      │  │  RabbitMQ    │                                 │
│  │  Processor   │  │  Publisher   │                                 │
│  └──────────────┘  └──────────────┘                                 │
└─────────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
deployguard/api/v2/
├── domain/                    # Domain Layer
│   ├── __init__.py
│   ├── entities.py           # Job, SecretFinding, AuditEntry
│   ├── value_objects.py      # JobStatus, SecretType, Severity, etc.
│   ├── events.py             # Domain events for Outbox Pattern
│   └── exceptions.py         # Domain-specific exceptions
│
├── application/              # Application Layer
│   ├── __init__.py
│   ├── ports.py              # Interfaces (repositories, services)
│   ├── dtos.py               # Data Transfer Objects
│   └── use_cases.py          # Business use cases
│
├── infrastructure/           # Infrastructure Layer
│   ├── __init__.py
│   ├── db_models.py          # SQLAlchemy models
│   ├── repositories.py       # Repository implementations
│   ├── unit_of_work.py       # Transaction management
│   ├── outbox_processor.py   # Outbox Pattern implementation
│   └── services.py           # External service implementations
│
├── container.py              # Dependency Injection
└── routes_clean.py           # Refactored API routes
```

## Outbox Pattern

The Outbox Pattern ensures reliable event publishing:

```
┌────────────────────────────────────────────────────────────────────┐
│ Transaction Boundary                                                │
│                                                                     │
│  1. Use Case executes business logic                               │
│  2. Job entity emits domain events                                 │
│  3. Save Job to database                                           │
│  4. Save domain events to Outbox table                             │
│  5. COMMIT transaction                                              │
│                                                                     │
│  [Both Job and Events saved atomically]                            │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│ Outbox Processor (Background Worker)                               │
│                                                                     │
│  1. Poll outbox table for unpublished messages                     │
│  2. Publish each message to RabbitMQ                               │
│  3. Mark message as published                                       │
│  4. Delete old published messages (cleanup)                        │
│                                                                     │
│  [Guarantees at-least-once delivery]                               │
└────────────────────────────────────────────────────────────────────┘
```

### Benefits

1. **Atomicity**: Events are saved in the same transaction as domain changes
2. **Reliability**: Events won't be lost even if RabbitMQ is temporarily down
3. **Ordering**: Events are processed in order of creation
4. **Idempotency**: Consumers should handle duplicate events (at-least-once)

## Domain Events

Events are emitted when significant things happen in the domain:

| Event | Trigger |
|-------|---------|
| `JobCreatedEvent` | New scan job created |
| `JobStatusChangedEvent` | Job status transitions |
| `ScanCompletedEvent` | Repository scan finishes |
| `SecretsSelectedEvent` | User selects secrets to clean |
| `CleaningStartedEvent` | Cleaning process begins |
| `CleaningCompletedEvent` | Cleaning process finishes |
| `PushStartedEvent` | Push to target begins |
| `PushCompletedEvent` | Push to target finishes |
| `JobFailedEvent` | Job fails with error |
| `JobCancelledEvent` | User cancels job |
| `JobExpiredEvent` | Job expires automatically |

## Value Objects

Value objects are immutable and defined by their attributes:

| Value Object | Purpose |
|--------------|---------|
| `JobStatus` | Enum with state machine transitions |
| `SecretType` | Type of secret (API key, password, etc.) |
| `Severity` | Severity level (critical, high, medium, low) |
| `JobId` | UUID validation and generation |
| `UserId` | User identifier validation |
| `SecretHash` | SHA256 hash of secret values |
| `SecretPreview` | Masked preview of secrets |
| `RepositoryUrl` | URL validation and credential injection |
| `Platform` | Supported platform validation |

## Use Cases

Each use case represents a single business operation:

| Use Case | Description |
|----------|-------------|
| `CreateScanJobUseCase` | Create new job and emit event |
| `ExecuteScanUseCase` | Execute repository scan |
| `SelectSecretsUseCase` | Select secrets for cleaning |
| `StartCleaningUseCase` | Initiate cleaning process |
| `ExecuteCleaningUseCase` | Execute history cleaning |
| `PushRepositoryUseCase` | Push to target repository |
| `GetJobUseCase` | Retrieve job details |
| `ListJobsUseCase` | List jobs with pagination |
| `CancelJobUseCase` | Cancel running job |

## Dependency Injection

The `Container` class manages dependencies:

```python
from deployguard.api.v2.container import get_container

container = get_container()

# Get use case with all dependencies injected
use_case = container.create_scan_job_use_case()
result = await use_case.execute(request)
```

## Database Schema

### Jobs Table
- Stores job metadata and status
- Optimistic locking via `version` column
- Indexes for user queries and expiration checks

### Secrets Table
- Stores found secrets with masked preview
- Foreign key to jobs with cascade delete
- Index on `selected_for_cleaning` for cleanup queries

### Audit Logs Table
- Immutable audit trail
- JSON details for flexible metadata
- Indexed by user and action

### Outbox Table
- Stores unpublished domain events
- Retry tracking for failed publishes
- Cleanup of old published messages

## Running the Outbox Processor

The outbox processor runs as a separate background worker:

```python
import asyncio
from deployguard.api.v2.infrastructure.outbox_processor import (
    OutboxProcessor, RabbitMQEventPublisher
)
from deployguard.api.v2.infrastructure.repositories import SQLAlchemyOutboxRepository

# Create components
publisher = RabbitMQEventPublisher("amqp://guest:guest@localhost:5672/")
await publisher.connect()

# Create processor
processor = OutboxProcessor(
    outbox_repository=outbox_repo,
    event_publisher=publisher,
    poll_interval_seconds=1.0,
    batch_size=100,
    max_retries=5,
)

# Run processor
await processor.start()  # Runs until stopped
```

## Testing

The clean architecture makes testing easier:

```python
# Unit test use case with mocked dependencies
class MockJobRepository:
    async def save(self, job): pass
    async def get_by_id(self, job_id): return mock_job

class MockUnitOfWork:
    jobs = MockJobRepository()
    # ... other mocks

use_case = CreateScanJobUseCase(uow=MockUnitOfWork(), ...)
result = await use_case.execute(request)
assert result.is_success
```

## Migration Guide

To migrate from the old routes to clean architecture:

1. Import the new router:
   ```python
   from deployguard.api.v2.routes_clean import router
   ```

2. Register with FastAPI:
   ```python
   app.include_router(router)
   ```

3. Configure environment:
   ```bash
   export DATABASE_URL=postgresql+asyncpg://user:pass@host/db
   export RABBITMQ_URL=amqp://guest:guest@localhost:5672/
   export STORAGE_PATH=/tmp/deployguard
   ```

4. Run database migrations (Alembic)

5. Start outbox processor as separate service
