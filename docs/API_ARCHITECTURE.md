# DeployGuard API v2 - Architecture Documentation

## Overview

DeployGuard API v2 is a scalable, Kubernetes-native service for automated repository security scanning and cleaning. It transforms the CLI tool into a multi-tenant API service capable of handling hundreds of concurrent users.

**Important**: The CLI and API are independent. The CLI operates directly without RabbitMQ or any queue dependencies. The API requires RabbitMQ for background job processing.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                   CLIENTS                                        │
│                                                                                  │
│    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                     │
│    │ Admin Panel  │    │   CI/CD      │    │  External    │                     │
│    │   (React)    │    │  Pipelines   │    │   Services   │                     │
│    └──────┬───────┘    └──────┬───────┘    └──────┬───────┘                     │
│           │                   │                   │                              │
└───────────┼───────────────────┼───────────────────┼──────────────────────────────┘
            │                   │                   │
            └───────────────────┼───────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            KUBERNETES CLUSTER                                    │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                         INGRESS CONTROLLER                               │   │
│  │                    (nginx / traefik / istio)                            │   │
│  └─────────────────────────────────┬───────────────────────────────────────┘   │
│                                    │                                            │
│  ┌─────────────────────────────────▼───────────────────────────────────────┐   │
│  │                        AUTH GATEWAY (Optional)                           │   │
│  │              Validates JWT, adds X-User-ID header                        │   │
│  └─────────────────────────────────┬───────────────────────────────────────┘   │
│                                    │                                            │
│  ┌─────────────────────────────────▼───────────────────────────────────────┐   │
│  │                         DEPLOYGUARD API                                  │   │
│  │                     (FastAPI - 3 replicas)                              │   │
│  │                                                                          │   │
│  │   GET  /health        - Basic health check                              │   │
│  │   GET  /health/ready  - Readiness check (all services)                  │   │
│  │   POST /jobs          - Create scan job                                 │   │
│  │   GET  /jobs/{id}     - Get job status                                  │   │
│  │   POST /jobs/{id}/clean - Start cleanup                                 │   │
│  │   GET  /jobs/{id}/download - Download cleaned repo                      │   │
│  │   POST /jobs/{id}/push - Push to target                                 │   │
│  └───────┬─────────────────────────┬───────────────────────────────────────┘   │
│          │                         │                       │                    │
│          ▼                         ▼                       ▼                    │
│  ┌───────────────┐    ┌────────────────────┐    ┌─────────────────────────┐   │
│  │   RabbitMQ    │    │    PostgreSQL      │    │     MinIO / S3          │   │
│  │   (Broker)    │    │    (Metadata +     │    │    (File Storage)       │   │
│  │               │    │    Task Results)   │    │                         │   │
│  │  Job Queue    │    │  - Jobs            │    │  - Cloned repos         │   │
│  │  Dead Letter  │    │  - Secrets found   │    │  - Scan reports         │   │
│  │  Exchange     │    │  - Audit logs      │    │  - Cleaned archives     │   │
│  │               │    │  - Task results    │    │                         │   │
│  └───────┬───────┘    └────────────────────┘    └─────────────────────────┘   │
│          │                                                                      │
│          ▼                                                                      │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                        CELERY WORKERS                                    │   │
│  │                     (5-20 replicas, HPA)                                │   │
│  │                                                                          │   │
│  │   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                   │   │
│  │   │  Worker 1   │   │  Worker 2   │   │  Worker N   │                   │   │
│  │   │             │   │             │   │             │                   │   │
│  │   │ scan_repo   │   │ clean_repo  │   │ push_repo   │                   │   │
│  │   │             │   │             │   │             │                   │   │
│  │   └─────────────┘   └─────────────┘   └─────────────┘                   │   │
│  │                                                                          │   │
│  │   Tasks: scan_repository_task, clean_repository_task, push_repository_task │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                        CELERY BEAT                                       │   │
│  │                     (1 replica - scheduler)                              │   │
│  │                                                                          │   │
│  │   Periodic Tasks:                                                        │   │
│  │   - cleanup_expired_jobs (hourly)                                       │   │
│  │   - storage_cleanup (daily)                                             │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           EXTERNAL SERVICES                                      │
│                                                                                  │
│    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                     │
│    │ Auth Service │    │   GitHub     │    │  Bitbucket   │                     │
│    │  (Your IAM)  │    │  Enterprise  │    │   Server     │                     │
│    └──────────────┘    └──────────────┘    └──────────────┘                     │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## CLI vs API Mode

DeployGuard supports two execution modes:

| Feature | CLI Mode | API Mode |
|---------|----------|----------|
| **Execution** | Direct, synchronous | Background, asynchronous |
| **RabbitMQ** | ❌ Not required | ✅ Required |
| **PostgreSQL** | ❌ Not required | ✅ Required |
| **MinIO/S3** | ❌ Not required | ✅ Required |
| **Multi-tenant** | ❌ Single user | ✅ Hundreds of users |
| **Use Case** | Local development, CI/CD | Enterprise service |

### CLI Usage (No RabbitMQ)
```bash
# Direct execution - no queue dependencies
deployguard scan --repo-path /path/to/repo
deployguard clean --repo-path /path/to/repo --secret-id abc123
deployguard push --repo-path /path/to/repo --target-url https://github.com/org/repo
```

### API Usage (Requires RabbitMQ)
```bash
# Background job processing
curl -X POST http://api/v2/jobs -d '{"source_url": "..."}'
# Returns immediately with job_id, worker processes in background
```

## Core Components

### 1. API Service (FastAPI)

**Purpose**: HTTP interface for all operations

**Endpoints**:
| Method | Endpoint | Description | Requires Broker |
|--------|----------|-------------|-----------------|
| GET | `/api/v2/health` | Basic health check | ❌ |
| GET | `/api/v2/health/ready` | Readiness check (all services) | ❌ |
| POST | `/api/v2/jobs` | Create new scan job | ✅ |
| GET | `/api/v2/jobs` | List user's jobs | ❌ |
| GET | `/api/v2/jobs/{id}` | Get job details + secrets | ❌ |
| DELETE | `/api/v2/jobs/{id}` | Cancel and cleanup job | ❌ |
| GET | `/api/v2/jobs/{id}/secrets` | List found secrets | ❌ |
| POST | `/api/v2/jobs/{id}/secrets/select` | Select secrets to clean | ❌ |
| POST | `/api/v2/jobs/{id}/clean` | Start cleaning process | ✅ |
| GET | `/api/v2/jobs/{id}/download` | Download cleaned repo | ❌ |
| POST | `/api/v2/jobs/{id}/push` | Push to target repo | ✅ |

**Graceful Degradation**: Endpoints that require the broker return HTTP 503 if RabbitMQ is unavailable.

**Scaling**: Horizontal (3+ replicas recommended)

### 2. RabbitMQ (Message Broker)

**Purpose**: Reliable message queue for background tasks

**Why RabbitMQ over Redis**:
- Better for long-running tasks (minutes to hours)
- Message acknowledgment ensures no task loss
- Dead letter queues for failed tasks
- Better visibility with management UI
- Persistent messages survive broker restarts

**Queues**:
| Queue | Purpose | Priority |
|-------|---------|----------|
| `deployguard` | Default queue | Normal |
| `deployguard.scan` | Repository scanning | High |
| `deployguard.clean` | History cleaning | Normal |
| `deployguard.push` | Push operations | Low |

**Management UI**: Available on port 15672

**Connection Resilience**:
```python
celery_app.conf.update(
    broker_connection_retry_on_startup=True,
    broker_connection_retry=True,
    broker_connection_max_retries=10,
)
```

### 3. Celery Workers

**Purpose**: Background task processing for long-running Git operations

**How Workers Connect to the Service**:
```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        WORKER ↔ SERVICE CONNECTION                            │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────┐                                    ┌─────────────┐        │
│   │  API Server │ ────POST /jobs────────────────────►│  RabbitMQ   │        │
│   │  (FastAPI)  │                                    │   (Queue)   │        │
│   └─────────────┘                                    └──────┬──────┘        │
│         │                                                   │               │
│         │                                                   │ AMQP          │
│         │                                                   ▼               │
│         │                                    ┌─────────────────────────┐    │
│         │                                    │    Celery Worker        │    │
│         │                                    │                         │    │
│         │                                    │  1. Receive task from   │    │
│         │                                    │     RabbitMQ            │    │
│         │                                    │  2. Execute git clone/  │    │
│         │                                    │     scan/clean/push     │    │
│         │                                    │  3. Store files in S3   │    │
│         │                                    │  4. Update DB directly  │    │
│         │                                    │  5. Ack task completion │    │
│         │                                    └───────────┬─────────────┘    │
│         │                                                │                  │
│         │                                    ┌───────────▼───────────┐      │
│         │                                    │     PostgreSQL        │      │
│         └─────────────────────────────────────►  (Shared Database)   │      │
│                                              │                       │      │
│              Both API and Workers read/write │  - Jobs table         │      │
│              to the same database            │  - Secrets table      │      │
│                                              │  - Task results       │      │
│                                              └───────────────────────┘      │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Key Points**:
1. **No Direct API ↔ Worker Communication**: Workers don't call the API
2. **Shared Database**: Both API and workers connect to the same PostgreSQL
3. **Message Queue**: RabbitMQ passes task messages (job_id, user_id)
4. **Status Updates**: Workers update job status directly in the database
5. **File Storage**: Workers upload/download from MinIO, API generates presigned URLs

**Tasks**:
- `scan_repository_task`: Clone → Scan → Store results
- `clean_repository_task`: Download → Clean history → Upload
- `push_repository_task`: Download → Push to target

**Scaling**: Horizontal with HPA (2-20 replicas based on CPU/memory)

**Configuration**:
```python
worker_prefetch_multiplier = 1  # One task per worker
task_time_limit = 3600  # 1 hour max
task_soft_time_limit = 3300  # 55 min soft limit
task_acks_late = True  # Acknowledge after completion
task_reject_on_worker_lost = True  # Requeue if worker dies
```

### 4. PostgreSQL

**Purpose**: Persistent metadata storage and Celery result backend

**Tables**:
- `jobs`: Job tracking and status
- `secrets_found`: Detected secrets with selection state
- `audit_logs`: Compliance audit trail
- `celery_taskmeta`: Task results (used by Celery)

**Why PostgreSQL for Results (not Redis)**:
- Durability: Results survive restarts
- Queryable: Can analyze task history
- Single database: Simpler infrastructure

### 5. MinIO/S3

**Purpose**: Large file storage

**Buckets**:
- `repos/{job_id}/source/`: Cloned repository
- `reports/{job_id}/`: Scan reports
- `cleaned/{job_id}/`: Cleaned repository archives

**Lifecycle**: Auto-delete after 7 days (configurable)

## Kubernetes Deployment

### Component Overview

| Component | Replicas | Purpose | Image |
|-----------|----------|---------|-------|
| `deployguard-api` | 3 | REST API | `deployguard/api:latest` |
| `deployguard-worker` | 5-20 (HPA) | Background tasks | `deployguard/api:latest` |
| `deployguard-beat` | 1 | Scheduled tasks | `deployguard/api:latest` |
| `postgres` | 1 | Database | `postgres:15-alpine` |
| `rabbitmq` | 1 | Message broker | `rabbitmq:3-management-alpine` |
| `minio` | 1 | Object storage | `minio/minio:latest` |

### Worker Deployment Details

Workers use the **same image** as the API but with a different command:

```yaml
# API Pod
containers:
- name: api
  image: deployguard/api:latest
  command: ["uvicorn", "deployguard.api.v2.main:app", "--host", "0.0.0.0"]

# Worker Pod  
containers:
- name: worker
  image: deployguard/api:latest
  command: ["celery", "-A", "deployguard.api.v2.tasks", "worker", "--loglevel=info", "--concurrency=1"]

# Beat Pod (scheduler)
containers:
- name: beat
  image: deployguard/api:latest
  command: ["celery", "-A", "deployguard.api.v2.tasks", "beat", "--loglevel=info"]
```

### Environment Variables

All components share the same environment:

```yaml
envFrom:
- configMapRef:
    name: deployguard-config
- secretRef:
    name: deployguard-secrets
```

**ConfigMap**:
```yaml
DATABASE_URL: "postgresql://deployguard:$(DB_PASSWORD)@postgres:5432/deployguard"
CELERY_BROKER_URL: "amqp://deployguard:$(RABBITMQ_PASSWORD)@rabbitmq:5672//"
CELERY_RESULT_BACKEND: "db+postgresql://deployguard:$(DB_PASSWORD)@postgres:5432/deployguard"
S3_ENDPOINT_URL: "http://minio:9000"
```

**Secrets**:
```yaml
DB_PASSWORD: "your-secure-db-password"
RABBITMQ_PASSWORD: "your-secure-rabbitmq-password"
S3_ACCESS_KEY: "minioadmin"
S3_SECRET_KEY: "minioadmin"
```

### Horizontal Pod Autoscaler

Workers scale automatically based on load:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: deployguard-worker-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: deployguard-worker
  minReplicas: 2
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

## Workflow Sequence

```
┌────────┐     ┌─────┐     ┌──────────┐     ┌────────┐     ┌───────┐
│ Client │     │ API │     │ RabbitMQ │     │ Worker │     │ MinIO │
└───┬────┘     └──┬──┘     └────┬─────┘     └───┬────┘     └───┬───┘
    │             │             │              │              │
    │ POST /jobs  │             │              │              │
    │────────────>│             │              │              │
    │             │             │              │              │
    │             │ Queue task  │              │              │
    │             │────────────>│              │              │
    │             │             │              │              │
    │  job_id     │             │              │              │
    │<────────────│             │              │              │
    │             │             │              │              │
    │             │             │ Dequeue      │              │
    │             │             │─────────────>│              │
    │             │             │              │              │
    │             │             │              │ Clone repo   │
    │             │             │              │─────────────>│
    │             │             │              │              │
    │             │             │              │ Scan         │
    │             │             │              │──────┐       │
    │             │             │              │<─────┘       │
    │             │             │              │              │
    │             │             │              │ Upload       │
    │             │             │              │─────────────>│
    │             │             │              │              │
    │             │             │              │ Delete local │
    │             │             │              │──────┐       │
    │             │             │              │<─────┘       │
    │             │             │              │              │
    │             │             │              │ Update DB    │
    │             │             │              │──────┐       │
    │             │             │              │<─────┘       │
    │             │             │              │              │
    │             │             │ Ack complete │              │
    │             │             │<─────────────│              │
    │             │             │              │              │
    │ GET /jobs/{id}            │              │              │
    │────────────>│             │              │              │
    │             │             │              │              │
    │  secrets[]  │             │              │              │
    │<────────────│             │              │              │
```

## Disk Management Strategy

### Problem
Repositories can be large (GBs), and hundreds of concurrent users could exhaust disk space.

### Solution

1. **Object Storage for Persistence**
   - All repos stored in MinIO/S3, not local disk
   - Workers use ephemeral temp directories

2. **Worker Temp Storage**
   - EmptyDir volumes with size limits (10GB)
   - Automatic cleanup on task completion
   - Try/finally ensures cleanup even on errors

3. **Automatic Expiration**
   - Jobs expire after 7 days
   - Celery Beat runs hourly cleanup
   - Deletes storage + updates job status

4. **Storage Lifecycle**
   ```
   Clone → Upload to S3 → Delete local
   Download → Process → Upload result → Delete local
   Push complete → Delete S3 data
   ```

## Authentication Integration

### Option 1: Header-based (Recommended)

Your auth gateway adds `X-User-ID` header after validating JWT:

```
Client → [JWT] → Auth Gateway → [X-User-ID: user123] → DeployGuard API
```

### Option 2: External Auth Service

API calls your auth service to validate credentials:

```python
class CredentialService:
    @staticmethod
    def get_credentials(credential_id: str, user_id: str) -> Dict[str, str]:
        response = requests.get(
            f"{AUTH_SERVICE_URL}/api/credentials/{credential_id}",
            headers={"X-User-ID": user_id}
        )
        return response.json()  # {"username": "...", "token": "..."}
```

## Scaling Considerations

### API Pods
- Stateless, scale horizontally
- Recommended: 3+ replicas for HA
- Resource: 256MB-512MB RAM, 0.25-0.5 CPU

### Worker Pods
- Resource intensive (git operations)
- Recommended: 2-20 replicas with HPA
- Resource: 512MB-2GB RAM, 0.5-1 CPU
- Concurrency: 1 task per worker (isolation)

### Auto-scaling Triggers
```yaml
metrics:
- type: Resource
  resource:
    name: cpu
    target:
      type: Utilization
      averageUtilization: 70
```

## Security Considerations

### 1. Credential Handling
- Never store Git credentials in DeployGuard DB
- Fetch from external auth service on-demand
- Credentials injected into clone URL in memory only

### 2. Secret Storage
- Full secret values never stored in DB
- Only preview (first/last 3 chars) and hash
- Full values only in scan report (S3, encrypted)

### 3. Network Security
- Internal services: ClusterIP only
- External: Ingress with TLS
- MinIO: Internal only, presigned URLs for download

### 4. Audit Trail
- All actions logged with user ID, timestamp, IP
- Compliance-ready audit_logs table

## Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:pass@host:5432/deployguard

# Celery (RabbitMQ)
CELERY_BROKER_URL=amqp://user:pass@rabbitmq:5672//
CELERY_RESULT_BACKEND=db+postgresql://user:pass@host:5432/deployguard

# Object Storage
S3_ENDPOINT_URL=http://minio:9000
S3_ACCESS_KEY=minioadmin
S3_SECRET_KEY=minioadmin
S3_BUCKET=deployguard

# External Services
AUTH_SERVICE_URL=http://auth-service:8080

# Application
CORS_ORIGINS=*
LOG_LEVEL=INFO
```

## Local Development

```bash
# Start all services
docker-compose -f docker-compose.api.yaml up -d

# View logs
docker-compose -f docker-compose.api.yaml logs -f worker

# Access services
# API: http://localhost:8000/docs
# RabbitMQ Management: http://localhost:15672 (guest/guest)
# MinIO Console: http://localhost:9001
# Flower (Celery monitor): http://localhost:5555
```

## Health Checks

### Basic Health (API is running)
```bash
curl http://localhost:8000/api/v2/health
# {"status": "healthy", "service": "deployguard-api"}
```

### Readiness (All services available)
```bash
curl http://localhost:8000/api/v2/health/ready
# {"status": "ready", "services": {"rabbitmq": true, "storage": true, "database": true}}

# If services unavailable:
# HTTP 503
# {"status": "not_ready", "services": {"rabbitmq": false, ...}, "message": "..."}
```

## API Usage Examples

### 1. Create Scan Job

```bash
curl -X POST http://localhost:8000/api/v2/jobs \
  -H "Content-Type: application/json" \
  -H "X-User-ID: user123" \
  -d '{
    "source_platform": "bitbucket",
    "source_url": "https://bitbucket.example.com/scm/proj/repo.git",
    "source_branch": "main",
    "source_credentials_id": "cred-abc-123"
  }'

# Response:
{
  "id": "job-uuid-here",
  "status": "pending",
  "progress_percent": 0
}
```

### 2. Check Status

```bash
curl http://localhost:8000/api/v2/jobs/job-uuid-here \
  -H "X-User-ID: user123"

# Response:
{
  "job": {
    "id": "job-uuid-here",
    "status": "awaiting_selection",
    "total_secrets_found": 15
  },
  "secrets": [
    {
      "id": "secret-1",
      "secret_type": "password",
      "secret_value_preview": "abc...xyz",
      "file_path": "config/database.yml",
      "selected_for_cleaning": true
    }
  ]
}
```

### 3. Select Secrets & Clean

```bash
# Select secrets
curl -X POST http://localhost:8000/api/v2/jobs/job-uuid-here/secrets/select \
  -H "Content-Type: application/json" \
  -H "X-User-ID: user123" \
  -d '{
    "secret_ids": ["secret-1", "secret-2", "secret-3"],
    "mark_false_positives": ["secret-4"]
  }'

# Start cleaning
curl -X POST http://localhost:8000/api/v2/jobs/job-uuid-here/clean \
  -H "X-User-ID: user123"
```

### 4. Download or Push

```bash
# Download
curl -L http://localhost:8000/api/v2/jobs/job-uuid-here/download \
  -H "X-User-ID: user123" \
  -o cleaned_repo.zip

# Or push to new repo
curl -X POST http://localhost:8000/api/v2/jobs/job-uuid-here/push \
  -H "Content-Type: application/json" \
  -H "X-User-ID: user123" \
  -d '{
    "target_platform": "github",
    "target_url": "https://github.example.com/org/new-repo.git",
    "target_credentials_id": "cred-xyz-789",
    "force_push": true
  }'
```

## Troubleshooting

### RabbitMQ Connection Issues

```bash
# Check RabbitMQ status
kubectl exec -n deployguard deploy/rabbitmq -- rabbitmq-diagnostics check_running

# View queues
kubectl exec -n deployguard deploy/rabbitmq -- rabbitmqctl list_queues
```

### Worker Not Processing Tasks

```bash
# Check worker logs
kubectl logs -n deployguard -l app=deployguard-worker --tail=100

# Check Celery status
kubectl exec -n deployguard deploy/deployguard-worker -- celery -A deployguard.api.v2.tasks inspect active
```

### API Returns 503

This means RabbitMQ is unavailable. Check:
1. RabbitMQ pod is running
2. Credentials are correct
3. Network policies allow connection

## Future Enhancements

1. **Webhook Notifications**: Notify external systems on job completion
2. **GitHub App Integration**: Direct GitHub/GitLab app for easier auth
3. **Scheduled Scans**: Periodic scans of connected repositories
4. **Team Workspaces**: Share jobs within teams
5. **Secret Rotation**: Integrate with vault for automatic rotation
6. **Custom Rules**: User-defined secret patterns
