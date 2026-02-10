# Database Migrations

This directory contains Alembic migrations for DeployGuard API v2.

## Setup

```bash
# Initialize alembic (already done)
cd deployguard/api/v2
alembic init migrations

# Generate a new migration
alembic revision --autogenerate -m "Description of changes"

# Run migrations
alembic upgrade head

# Rollback one version
alembic downgrade -1
```

## Kubernetes Deployment

Migrations are automatically run via init container before the API starts.
See `k8s/deployment.yaml` for configuration.
