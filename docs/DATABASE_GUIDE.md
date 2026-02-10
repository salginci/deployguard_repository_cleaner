# DeployGuard - Database & Migration Guide

## Overview

DeployGuard uses PostgreSQL for persistent storage in API mode. This document covers:
- Database schema
- Migration management with Alembic
- Kubernetes deployment with automatic migrations

## Database Schema

### Core Tables

#### `jobs`
Tracks scan/clean jobs for each user.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| user_id | VARCHAR(255) | User identifier |
| source_platform | VARCHAR(50) | github, bitbucket, gitlab |
| source_url | VARCHAR(500) | Repository URL |
| status | ENUM | pending, scanning, completed, failed |
| total_secrets_found | INT | Count of detected secrets |
| created_at | TIMESTAMP | Job creation time |

#### `secrets_found`
Secrets detected during scans.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| job_id | UUID | Foreign key to jobs |
| secret_type | ENUM | api_key, password, token, etc. |
| secret_value_hash | VARCHAR(64) | SHA256 hash (not actual value) |
| file_path | VARCHAR(500) | File where found |
| selected_for_cleaning | BOOL | User's selection |
| is_false_positive | BOOL | Marked as false positive |

#### `audit_logs`
Compliance audit trail.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| job_id | UUID | Related job |
| user_id | VARCHAR(255) | Who performed action |
| action | VARCHAR(100) | scan_started, secret_cleaned, etc. |
| details | JSON | Additional context |

### Feedback Tables (ML Training)

#### `feedback_submissions`
User feedback submissions from CLI.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| client_id | VARCHAR(64) | Anonymous client hash |
| total_detected | INT | Total secrets scanned |
| confirmed_secrets | INT | User confirmed as real |
| false_positives | INT | User marked as false positive |
| received_at | TIMESTAMP | When received |

#### `feedback_items`
Individual secret classifications.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| submission_id | UUID | Parent submission |
| value_hash | VARCHAR(64) | Secret hash |
| value_pattern | VARCHAR(255) | Pattern like "ghp_[alnum:36]" |
| is_true_positive | BOOL | True = real secret |

#### `known_false_positive_patterns`
Auto-generated from user feedback.

| Column | Type | Description |
|--------|------|-------------|
| pattern | VARCHAR(255) | Detection pattern |
| confidence | FLOAT | 0.0-1.0 confidence score |
| sample_count | INT | Number of samples |
| reason | VARCHAR(500) | Why it's a false positive |

## Migration Management

### Using Alembic

```bash
# Navigate to API v2 directory
cd deployguard/api/v2

# Generate new migration after model changes
alembic revision --autogenerate -m "Add new_feature"

# Run migrations
alembic upgrade head

# Rollback one version
alembic downgrade -1

# Show current version
alembic current

# Show migration history
alembic history
```

### Environment Variables

```bash
# Database connection
DATABASE_URL=postgresql://user:pass@host:5432/deployguard

# For development
DATABASE_URL=postgresql://deployguard:password@localhost:5432/deployguard
```

## Kubernetes Deployment

### Automatic Migrations

The Kubernetes deployment includes an **init container** that runs migrations before the API starts:

```yaml
spec:
  initContainers:
  - name: db-migrations
    image: deployguard/api:latest
    command: ["python", "-m", "alembic", "upgrade", "head"]
    workingDir: /app/deployguard/api/v2
    env:
    - name: DATABASE_URL
      value: "postgresql://..."
```

### Deployment Order

1. **PostgreSQL** starts first (via PVC)
2. **Init container** runs migrations
3. **API pods** start after migrations complete
4. **Workers** connect to same database

### Scaling Considerations

- Migrations run only once (in init container)
- Multiple API replicas share same database
- Use connection pooling (PgBouncer) for >10 replicas

## Development Setup

### Local Database

```bash
# Start PostgreSQL with Docker
docker run -d \
  --name deployguard-db \
  -e POSTGRES_DB=deployguard \
  -e POSTGRES_USER=deployguard \
  -e POSTGRES_PASSWORD=password \
  -p 5432:5432 \
  postgres:15-alpine

# Run migrations
cd deployguard/api/v2
DATABASE_URL=postgresql://deployguard:password@localhost:5432/deployguard \
  alembic upgrade head
```

### Running API Locally

```bash
# Set environment
export DATABASE_URL=postgresql://deployguard:password@localhost:5432/deployguard

# Run API
uvicorn deployguard.api.app:app --reload
```

## Backup & Recovery

### Backup

```bash
# Kubernetes
kubectl exec -n deployguard postgres-0 -- \
  pg_dump -U deployguard deployguard > backup.sql

# Docker
docker exec deployguard-db \
  pg_dump -U deployguard deployguard > backup.sql
```

### Restore

```bash
# Kubernetes
kubectl exec -i -n deployguard postgres-0 -- \
  psql -U deployguard deployguard < backup.sql
```

## Troubleshooting

### Migration Stuck

```bash
# Check alembic version table
psql -U deployguard -d deployguard -c "SELECT * FROM alembic_version;"

# Force to specific version
alembic stamp head  # Mark as up-to-date
alembic upgrade head  # Then try upgrade
```

### Connection Issues

```bash
# Test connection
psql postgresql://deployguard:password@localhost:5432/deployguard

# Check from Kubernetes
kubectl exec -n deployguard deployguard-api-xxx -- \
  python -c "from deployguard.api.v2.models import init_db; print('OK')"
```
