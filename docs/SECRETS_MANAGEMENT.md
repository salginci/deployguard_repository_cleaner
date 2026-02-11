# DeployGuard - Secrets Management Guide

## ⚠️ Important: Never Hardcode Secrets

This project requires several secrets for operation. **Never commit secrets to the repository.**

The `.env` file is for **local development only** and is listed in `.gitignore`.

## Required Secrets

| Secret | Environment Variable | Description |
|--------|---------------------|-------------|
| Database Password | `DB_PASSWORD` | PostgreSQL connection password |
| RabbitMQ Password | `RABBITMQ_PASSWORD` | Message broker authentication |
| S3 Access Key | `S3_ACCESS_KEY` | MinIO/S3 storage access |
| S3 Secret Key | `S3_SECRET_KEY` | MinIO/S3 storage secret |
| GitHub Token | `GITHUB_TOKEN` | GitHub API access (for scanning remote repos) |
| Feedback HMAC Secret | `FEEDBACK_HMAC_SECRET` | Request signing for feedback endpoint |

## Kubernetes Deployment

### Creating the Secret

Secrets must be created in Kubernetes **before** deploying the application:

```bash
# Create namespace if not exists
kubectl create namespace deployguard

# Create secret from literal values
kubectl create secret generic deployguard-secrets \
  --namespace deployguard \
  --from-literal=DB_PASSWORD='your-secure-db-password' \
  --from-literal=RABBITMQ_PASSWORD='your-secure-rabbitmq-password' \
  --from-literal=S3_ACCESS_KEY='your-s3-access-key' \
  --from-literal=S3_SECRET_KEY='your-s3-secret-key' \
  --from-literal=GITHUB_TOKEN='ghp_xxxxxxxxxxxx' \
  --from-literal=FEEDBACK_HMAC_SECRET='your-hmac-secret-key'
```

### Alternative: Create from YAML

```yaml
# DO NOT commit this file with real values!
# Use as template only
apiVersion: v1
kind: Secret
metadata:
  name: deployguard-secrets
  namespace: deployguard
type: Opaque
stringData:
  DB_PASSWORD: "REPLACE_ME"
  RABBITMQ_PASSWORD: "REPLACE_ME"
  S3_ACCESS_KEY: "REPLACE_ME"
  S3_SECRET_KEY: "REPLACE_ME"
  GITHUB_TOKEN: "REPLACE_ME"
  FEEDBACK_HMAC_SECRET: "REPLACE_ME"
```

### How Secrets Are Injected

The Kubernetes deployment references secrets via `secretRef`:

```yaml
spec:
  containers:
  - name: api
    image: deployguard/api:latest
    envFrom:
    - secretRef:
        name: deployguard-secrets  # <-- Secrets injected here
    - configMapRef:
        name: deployguard-config
```

All keys in the secret become environment variables in the container.

## External Secret Management (Recommended for Production)

For production environments, use an external secret manager:

### Option 1: HashiCorp Vault

```yaml
# Using Vault Agent Injector
apiVersion: apps/v1
kind: Deployment
metadata:
  name: deployguard-api
spec:
  template:
    metadata:
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "deployguard"
        vault.hashicorp.com/agent-inject-secret-db: "secret/data/deployguard/db"
```

### Option 2: AWS Secrets Manager

```yaml
# Using External Secrets Operator
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: deployguard-secrets
  namespace: deployguard
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: ClusterSecretStore
  target:
    name: deployguard-secrets
  data:
  - secretKey: DB_PASSWORD
    remoteRef:
      key: deployguard/production
      property: db_password
  - secretKey: GITHUB_TOKEN
    remoteRef:
      key: deployguard/production
      property: github_token
```

### Option 3: Azure Key Vault

```yaml
# Using Azure Key Vault Provider
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: deployguard-secrets
spec:
  provider: azure
  parameters:
    keyvaultName: "your-keyvault-name"
    objects: |
      array:
        - |
          objectName: db-password
          objectType: secret
        - |
          objectName: github-token
          objectType: secret
```

## Secret Rotation

### Rotating Database Password

```bash
# 1. Update secret in Kubernetes
kubectl create secret generic deployguard-secrets \
  --namespace deployguard \
  --from-literal=DB_PASSWORD='new-password' \
  --dry-run=client -o yaml | kubectl apply -f -

# 2. Restart deployments to pick up new secret
kubectl rollout restart deployment/deployguard-api -n deployguard
kubectl rollout restart deployment/deployguard-worker -n deployguard
```

### Rotating GitHub Token

1. Generate new token in GitHub Settings → Developer Settings → Personal Access Tokens
2. Update Kubernetes secret
3. Restart API deployment

## Local Development

For local development, create a `.env` file (never commit!):

```bash
# Copy the template
cp .env.example .env

# Edit with your values
nano .env
```

Example `.env`:
```dotenv
# Database
DB_PASSWORD=local-dev-password

# GitHub (use a separate token for development)
GITHUB_TOKEN=ghp_your_dev_token

# S3/MinIO
S3_ACCESS_KEY=minioadmin
S3_SECRET_KEY=minioadmin
```

## CI/CD Pipeline Secrets

### GitHub Actions

Store secrets in repository settings → Secrets and variables → Actions:

```yaml
# .github/workflows/deploy.yml
jobs:
  deploy:
    steps:
    - name: Deploy to Kubernetes
      env:
        KUBE_CONFIG: ${{ secrets.KUBE_CONFIG }}
      run: |
        # Secrets are injected from GitHub, not from code
        kubectl apply -f k8s/
```

### GitLab CI

```yaml
# .gitlab-ci.yml
deploy:
  script:
    - kubectl create secret generic deployguard-secrets
        --from-literal=DB_PASSWORD=$DB_PASSWORD
        --from-literal=GITHUB_TOKEN=$GITHUB_TOKEN
        --dry-run=client -o yaml | kubectl apply -f -
  variables:
    DB_PASSWORD: $DB_PASSWORD  # From GitLab CI/CD Variables
    GITHUB_TOKEN: $GITHUB_TOKEN
```

## Checklist Before Deployment

- [ ] All secrets created in Kubernetes namespace
- [ ] No secrets hardcoded in ConfigMaps
- [ ] `.env` file is in `.gitignore`
- [ ] No secrets in Docker images
- [ ] Secret rotation plan documented
- [ ] Access to secrets is limited (RBAC)

## Troubleshooting

### Pod not starting - secret not found

```bash
# Check if secret exists
kubectl get secrets -n deployguard

# Describe secret (shows keys, not values)
kubectl describe secret deployguard-secrets -n deployguard
```

### Environment variable not set

```bash
# Check env vars in running pod
kubectl exec -n deployguard deployguard-api-xxx -- env | grep -i password

# Should show the variable (value redacted in output)
```

### Secret not updating after rotation

```bash
# Secrets are loaded at pod startup, restart to pick up changes
kubectl rollout restart deployment/deployguard-api -n deployguard
```
