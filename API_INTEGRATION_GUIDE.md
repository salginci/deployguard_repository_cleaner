# DeployGuard API Integration Guide

> **For AI Assistants**: This document provides complete context for integrating DeployGuard API into a control panel application. Use this as your primary reference.

## Overview

DeployGuard is a secret detection and remediation tool that scans Git repositories for exposed secrets (API keys, passwords, tokens, etc.). This API is designed to run **behind a BFF (Backend For Frontend)** - no JWT authentication is implemented.

**Repository**: https://github.com/salginci/deployguard_repository_cleaner  
**PyPI Package**: `deployguard-repo-guard`  
**API Base URL**: Configured per deployment (default: `http://localhost:8000`)

---

## Architecture

```
┌─────────────────┐     ┌─────────────┐     ┌──────────────────┐
│  Control Panel  │────▶│    BFF      │────▶│  DeployGuard API │
│   (Frontend)    │     │  (Your API) │     │   (This Service) │
└─────────────────┘     └─────────────┘     └──────────────────┘
                              │
                              ▼
                        User Management
                        (Your Database)
```

- **Control Panel**: Your admin UI where users manage repositories
- **BFF**: Your backend that handles user auth, stores user_ids, proxies to DeployGuard
- **DeployGuard API**: This service - handles source control connections and scanning

---

## User Flow

```
1. User logs into Control Panel
2. User clicks "Add Repository"
3. Panel shows: GitHub | Bitbucket buttons
4. User clicks GitHub → shown instructions to create PAT
5. User creates PAT on GitHub, pastes into panel
6. API validates token, returns user's repositories
7. User selects a repository
8. User can now: Scan, View Results, Remediate
```

---

## API Endpoints

### Base URL
All endpoints are prefixed with `/api/v1` except health checks.

---

## 1. Health & Status

### Health Check
```http
GET /health
```
**Response:**
```json
{
  "status": "healthy",
  "version": "0.1.6",
  "patterns_loaded": 961,
  "uptime_seconds": 3600.5
}
```

### Kubernetes Probes
```http
GET /ready   → {"ready": true}
GET /live    → {"alive": true}
```

---

## 2. Source Control Providers

### List Available Providers
```http
GET /api/v1/providers
```
**Response:**
```json
{
  "providers": [
    {
      "id": "github",
      "name": "GitHub",
      "icon": "github",
      "token_url": "https://github.com/settings/tokens/new",
      "instructions": [
        "Go to GitHub → Settings → Developer settings → Personal access tokens",
        "Click 'Generate new token (classic)'",
        "Select scopes: 'repo' (full control of private repos)",
        "Click 'Generate token' and copy it"
      ],
      "required_scopes": ["repo"]
    },
    {
      "id": "bitbucket",
      "name": "Bitbucket",
      "icon": "bitbucket",
      "token_url": "https://bitbucket.org/account/settings/app-passwords/new",
      "instructions": [
        "Go to Bitbucket → Personal settings → App passwords",
        "Click 'Create app password'",
        "Select permissions: Repositories (Read, Write)",
        "Click 'Create' and copy the password",
        "You'll also need your Bitbucket username"
      ],
      "required_scopes": ["repository:read", "repository:write"]
    }
  ]
}
```

---

## 3. Connect Source Control Account

### Connect with Personal Access Token
```http
POST /api/v1/connect?user_id={user_id}
Content-Type: application/json

{
  "provider": "github",
  "token": "ghp_xxxxxxxxxxxxxxxxxxxx"
}
```

**For Bitbucket** (requires username):
```json
{
  "provider": "bitbucket",
  "token": "app_password_here",
  "username": "bitbucket_username"
}
```

**Response (Success):**
```json
{
  "connected": true,
  "provider": "github",
  "username": "johndoe",
  "name": "John Doe",
  "avatar_url": "https://avatars.githubusercontent.com/u/12345"
}
```

**Response (Invalid Token):**
```json
{
  "detail": "Invalid token or insufficient permissions"
}
```
Status: `401`

---

### List Connected Accounts
```http
GET /api/v1/accounts?user_id={user_id}
```
**Response:**
```json
{
  "accounts": [
    {
      "provider": "github",
      "username": "johndoe",
      "name": "John Doe",
      "avatar_url": "https://...",
      "connected_at": "2026-02-04T10:30:00Z"
    }
  ]
}
```

---

### Disconnect Account
```http
DELETE /api/v1/disconnect/{provider}?user_id={user_id}
```
**Response:**
```json
{
  "disconnected": true
}
```

---

## 4. Repository Management

### List Repositories from Provider
```http
GET /api/v1/repositories?provider=github&user_id={user_id}&page=1&per_page=30&search=myapp
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| provider | string | Yes | `github` or `bitbucket` |
| user_id | string | Yes | Your system's user ID |
| page | int | No | Page number (default: 1) |
| per_page | int | No | Items per page (default: 30, max: 100) |
| search | string | No | Filter by name/description |

**Response:**
```json
{
  "repositories": [
    {
      "full_name": "johndoe/my-app",
      "name": "my-app",
      "owner": "johndoe",
      "description": "My awesome application",
      "private": true,
      "default_branch": "main",
      "clone_url": "https://github.com/johndoe/my-app.git",
      "updated_at": "2026-02-01T15:00:00Z",
      "language": "Python"
    }
  ],
  "page": 1,
  "per_page": 30,
  "provider": "github"
}
```

---

### Select Repository for Scanning
```http
POST /api/v1/repositories/select?user_id={user_id}
Content-Type: application/json

{
  "provider": "github",
  "repo_full_name": "johndoe/my-app"
}
```

**Response:**
```json
{
  "selected": true,
  "repository": "johndoe/my-app",
  "provider": "github"
}
```

---

### List Selected Repositories
```http
GET /api/v1/repositories/selected?user_id={user_id}
```
**Response:**
```json
{
  "repositories": [
    {
      "full_name": "johndoe/my-app",
      "provider": "github",
      "selected_at": "2026-02-04T10:45:00Z"
    }
  ]
}
```

---

### Deselect Repository
```http
DELETE /api/v1/repositories/selected/{owner}/{repo}?user_id={user_id}
```
Example: `DELETE /api/v1/repositories/selected/johndoe/my-app?user_id=123`

**Response:**
```json
{
  "deselected": true
}
```

---

## 5. Repository Scanning

### Scan a Repository for Secrets
```http
POST /api/v1/repositories/{owner}/{repo}/scan?user_id={user_id}
Content-Type: application/json

{
  "scan_history": false,
  "verify_secrets": true,
  "branch": "main"
}
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| scan_history | bool | false | Scan entire git history (slower but thorough) |
| verify_secrets | bool | false | Test if secrets are active (API calls) |
| branch | string | null | Specific branch to scan (null = default branch) |

**Response:**
```json
{
  "repository": "johndoe/my-app",
  "provider": "github",
  "branch": "main",
  "scanned_at": "2026-02-04T11:00:00Z",
  "total_findings": 3,
  "by_severity": {
    "critical": 1,
    "high": 2,
    "medium": 0,
    "low": 0
  },
  "findings": [
    {
      "file": "config/settings.py",
      "line": 42,
      "type": "api_key",
      "severity": "critical",
      "pattern": "AWS Access Key",
      "preview": "AKIA****",
      "context": "AWS_ACCESS_KEY = 'AKIA...'",
      "verified": "verified_active"
    },
    {
      "file": ".env.example",
      "line": 15,
      "type": "token",
      "severity": "high",
      "pattern": "GitHub Token",
      "preview": "ghp_****",
      "context": "GITHUB_TOKEN=ghp_xxx",
      "verified": "verified_inactive"
    }
  ]
}
```

**Verification Status Values:**
- `verified_active` - Secret is valid and working
- `verified_inactive` - Secret is invalid/revoked
- `unverified` - Could not verify (unsupported type)
- `error` - Verification failed
- `null` - Verification not requested

---

## 6. Secret Verification (Standalone)

### Verify Secrets Directly
```http
POST /api/v1/verify
Content-Type: application/json

{
  "secrets": [
    {"type": "github_token", "value": "ghp_xxxx"},
    {"type": "stripe_api_key", "value": "sk_live_xxxx"}
  ],
  "timeout": 10
}
```

**Response:**
```json
{
  "verified": 2,
  "results": [
    {
      "type": "github_token",
      "status": "active",
      "message": "Secret is active"
    },
    {
      "type": "stripe_api_key",
      "status": "inactive",
      "message": "Secret is inactive or invalid"
    }
  ]
}
```

### List Supported Verification Types
```http
GET /api/v1/verify/types
```
**Response:**
```json
{
  "types": [
    "github_token", "github_pat", "gitlab_token",
    "aws_access_key", "stripe_api_key", "openai_api_key",
    "slack_bot_token", "sendgrid_api_key", "twilio_api_key",
    ... (40+ types supported)
  ],
  "total": 48
}
```

---

## 7. Pattern Management

### List Detection Patterns
```http
GET /api/v1/patterns?severity=critical&limit=50&offset=0&search=aws
```

| Parameter | Type | Description |
|-----------|------|-------------|
| severity | string | Filter: critical, high, medium, low, info |
| pattern_type | string | Filter: api_key, password, token, secret, etc. |
| search | string | Search in name/description |
| limit | int | Max results (default: 100) |
| offset | int | Pagination offset |

**Response:**
```json
{
  "patterns": [
    {
      "id": "aws_access_key",
      "name": "AWS Access Key",
      "description": "AWS access key ID starting with AKIA",
      "severity": "critical",
      "pattern_type": "api_key",
      "enabled": true
    }
  ],
  "total": 961
}
```

### Get Single Pattern
```http
GET /api/v1/patterns/{pattern_id}
```

### Pattern Statistics
```http
GET /api/v1/patterns/stats/summary
```
**Response:**
```json
{
  "total": 961,
  "by_severity": {
    "critical": 45,
    "high": 312,
    "medium": 401,
    "low": 203
  },
  "by_type": {
    "api_key": 456,
    "token": 234,
    "password": 89,
    ...
  }
}
```

---

## 8. Statistics

### Get Overall Stats
```http
GET /api/v1/stats
```
**Response:**
```json
{
  "total_scans": 150,
  "total_findings": 423,
  "total_patterns": 961,
  "findings_by_severity": {
    "critical": 23,
    "high": 156,
    "medium": 201,
    "low": 43
  },
  "findings_by_type": {
    "api_key": 189,
    "token": 134,
    ...
  },
  "top_patterns": [
    {"id": "generic_api_key", "count": 89},
    {"id": "aws_access_key", "count": 45}
  ]
}
```

---

## Integration Example (BFF Code)

### Express.js/Node.js Example
```javascript
// routes/repositories.js
const express = require('express');
const axios = require('axios');
const router = express.Router();

const DEPLOYGUARD_API = process.env.DEPLOYGUARD_API_URL || 'http://deployguard:8000';

// Middleware to get user_id from your auth
const getUserId = (req) => req.user.id; // Adjust based on your auth

// List providers
router.get('/providers', async (req, res) => {
  const response = await axios.get(`${DEPLOYGUARD_API}/api/v1/providers`);
  res.json(response.data);
});

// Connect provider
router.post('/connect', async (req, res) => {
  const { provider, token, username } = req.body;
  const response = await axios.post(
    `${DEPLOYGUARD_API}/api/v1/connect`,
    { provider, token, username },
    { params: { user_id: getUserId(req) } }
  );
  res.json(response.data);
});

// List repositories
router.get('/repositories', async (req, res) => {
  const { provider, page, per_page, search } = req.query;
  const response = await axios.get(`${DEPLOYGUARD_API}/api/v1/repositories`, {
    params: { provider, page, per_page, search, user_id: getUserId(req) }
  });
  res.json(response.data);
});

// Select repository
router.post('/repositories/select', async (req, res) => {
  const response = await axios.post(
    `${DEPLOYGUARD_API}/api/v1/repositories/select`,
    req.body,
    { params: { user_id: getUserId(req) } }
  );
  res.json(response.data);
});

// Scan repository
router.post('/repositories/:owner/:repo/scan', async (req, res) => {
  const { owner, repo } = req.params;
  const response = await axios.post(
    `${DEPLOYGUARD_API}/api/v1/repositories/${owner}/${repo}/scan`,
    req.body,
    { params: { user_id: getUserId(req) } }
  );
  res.json(response.data);
});

module.exports = router;
```

---

## Docker Deployment

### Docker Compose with Your App
```yaml
version: '3.8'

services:
  # Your admin panel backend
  admin-api:
    build: ./admin-api
    ports:
      - "3000:3000"
    environment:
      - DEPLOYGUARD_API_URL=http://deployguard:8000
    depends_on:
      - deployguard

  # DeployGuard API
  deployguard:
    image: deployguard:latest
    # Or build from source:
    # build:
    #   context: ./deployguard_repository_cleaner
    #   target: production
    ports:
      - "8000:8000"  # Optional: expose for debugging
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Your frontend
  admin-panel:
    build: ./admin-panel
    ports:
      - "80:80"
    depends_on:
      - admin-api
```

---

## Error Handling

All errors follow this format:
```json
{
  "detail": "Error message here"
}
```

| Status Code | Meaning |
|-------------|---------|
| 400 | Bad request (invalid parameters) |
| 401 | Not connected to provider / Invalid token |
| 404 | Resource not found |
| 500 | Internal server error |

---

## Data Storage Note

**Current Implementation**: In-memory storage (dictionaries)

For production, replace with your database:
- `_user_tokens` → Store in your users table or separate tokens table
- `_connected_repos` → Store in repositories table

The `user_id` parameter links everything to your system's user.

---

## Files Reference

| File | Purpose |
|------|---------|
| `deployguard/api/app.py` | FastAPI application factory |
| `deployguard/api/routes/repos.py` | Repository & provider endpoints |
| `deployguard/api/routes/scan.py` | Scanning endpoints |
| `deployguard/api/routes/verify.py` | Secret verification |
| `deployguard/api/routes/patterns.py` | Pattern management |
| `deployguard/api/routes/health.py` | Health checks |
| `deployguard/api/schemas.py` | Pydantic models |
| `deployguard/core/scanner.py` | Secret detection engine |
| `deployguard/core/verifier.py` | Secret verification (40+ services) |
| `deployguard/config/secret_patterns.yaml` | 961 detection patterns |

---

## Development Commands

```bash
# Install with API dependencies
pip install 'deployguard-repo-guard[api]'

# Run API locally
deployguard serve --port 8000 --reload

# Run with Docker
docker build --target production -t deployguard .
docker run -p 8000:8000 deployguard

# Run tests
pytest tests/ -v

# API docs
open http://localhost:8000/docs
```

---

## What Was Built (Context for Future Sessions)

### Core Features
1. **Secret Scanner** - Detects 961 patterns of secrets in code
2. **Secret Verifier** - Tests if secrets are active (40+ services: GitHub, AWS, Stripe, etc.)
3. **REST API** - FastAPI-based, designed for BFF integration
4. **CLI Tool** - `deployguard` command for local use

### API Design Decisions
- **No JWT**: Designed to run behind BFF that handles auth
- **user_id Parameter**: Links all resources to your user system
- **PAT-based Auth**: Users provide their own GitHub/Bitbucket tokens (no OAuth app needed)
- **In-memory Storage**: Replace with database for production

### Key Patterns
- Repositories are "selected" before scanning (user's working repos)
- Tokens are validated immediately on connect (fail fast)
- Scans clone to temp directory, scan, then cleanup
- Verification is optional (can be slow for many secrets)

---

## Changelog

| Version | Changes |
|---------|---------|
| 0.1.6 | Added REST API, PAT-based source control connection |
| 0.1.5 | Added secret verification (40+ services) |
| 0.1.4 | Fixed pre-commit hook severity handling |
| 0.1.3 | Initial PyPI release |
