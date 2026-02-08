# 🔄 DeployGuard Remediation Guide

Complete guide for remediating exposed secrets detected by DeployGuard.

---

## Table of Contents

- [Overview](#overview)
- [Remediation Workflow](#remediation-workflow)
- [Step-by-Step Instructions](#step-by-step-instructions)
  - [1. Identify Secrets](#1-identify-secrets)
  - [2. Extract Secrets](#2-extract-secrets)
  - [3. Update Code](#3-update-code)
  - [4. Configure Environment](#4-configure-environment)
  - [5. Clean Git History](#5-clean-git-history)
  - [6. Rotate Secrets](#6-rotate-secrets)
  - [7. Verify & Test](#7-verify--test)
- [Language-Specific Guides](#language-specific-guides)
- [CI/CD Integration](#cicd-integration)
- [GitHub Actions Secrets](#github-actions-secrets)
- [Best Practices](#best-practices)
- [Common Scenarios](#common-scenarios)

---

## Overview

**Secret remediation** is the process of removing hardcoded secrets from your codebase and replacing them with secure alternatives.

### What Gets Remediated?

- Hardcoded API keys
- Database passwords
- OAuth tokens
- Encryption keys
- Service credentials
- Connection strings
- Any sensitive configuration

### Remediation Goals

1. ✅ Remove all hardcoded secrets from code
2. ✅ Store secrets in environment variables or secret management systems
3. ✅ Clean secrets from git history
4. ✅ Rotate exposed secrets
5. ✅ Prevent future secret commits

---

## Remediation Workflow

```
┌─────────────────┐
│  1. Scan Code   │  ← deployguard scan local --path .
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 2. Extract      │  ← deployguard remediate extract
│    Secrets      │     → Creates .env.example
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 3. Update Code  │  ← Manual or auto-update
│    to Use ENV   │     → Replace hardcoded values
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 4. Configure    │  ← Create .env, add to CI/CD
│    Environment  │     → Set up GitHub Secrets
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 5. Clean Git    │  ← deployguard clean history --execute
│    History      │     → Remove from all commits
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 6. Rotate       │  ← Invalidate old secrets
│    Secrets      │     → Generate new ones
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 7. Verify &     │  ← deployguard verify
│    Test         │     → Ensure everything works
└─────────────────┘
```

---

## Step-by-Step Instructions

### 1. Identify Secrets

**Scan your repository:**

```bash
# Scan current directory
deployguard scan local --path . --output findings.json

# Review findings
cat findings.json | jq '.summary'
```

**Example output:**
```json
{
  "total_findings": 15,
  "by_type": {
    "aws_access_key": 3,
    "generic_password": 5,
    "jwt_token": 2,
    "database_url": 3,
    "api_key": 2
  }
}
```

**Review each finding:**
```bash
cat findings.json | jq '.findings[] | {type, file, line, value}'
```

---

### 2. Extract Secrets

**Automatically extract secrets to environment variables:**

```bash
# Extract to .env.example
deployguard remediate extract --findings findings.json --output .env.example

# Or extract to YAML
deployguard remediate extract --findings findings.json --output secrets.yml --format yaml
```

**Generated .env.example:**
```env
# AWS Credentials (from config/aws.py:12)
AWS_ACCESS_KEY=AKIA****************
AWS_SECRET_KEY=****************************************

# Database (from config/database.py:8)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=myapp
DB_USER=admin
DB_PASSWORD=****************************************

# API Keys (from services/stripe.py:15)
STRIPE_API_KEY=sk_test_********************************
STRIPE_WEBHOOK_SECRET=whsec_******************************

# External Services
SENDGRID_API_KEY=SG.************************************
GOOGLE_MAPS_API_KEY=AIza***********************************
```

**Create actual .env file:**
```bash
# Copy template and fill in real values
cp .env.example .env

# Edit .env with actual secret values
nano .env
```

**Add .env to .gitignore:**
```bash
echo ".env" >> .gitignore
echo ".env.local" >> .gitignore
echo ".env.production" >> .gitignore
```

---

### 3. Update Code

#### Option A: Automated Code Updates

```bash
# Preview changes (dry-run)
deployguard remediate update-code --findings findings.json --language javascript --dry-run

# Apply changes
deployguard remediate update-code --findings findings.json --language javascript
```

#### Option B: Manual Code Updates

See [Language-Specific Guides](#language-specific-guides) below.

---

### 4. Configure Environment

#### Local Development

**Create .env file:**
```env
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DB_PASSWORD=MyS3cr3tP@ssw0rd!
STRIPE_API_KEY=sk_test_51HxKJ2eZvKY3qBdz...
```

**Load environment variables:**

**JavaScript/Node.js:**
```bash
npm install dotenv
```
```javascript
require('dotenv').config();
const apiKey = process.env.STRIPE_API_KEY;
```

**Python:**
```bash
pip install python-dotenv
```
```python
from dotenv import load_dotenv
load_dotenv()
api_key = os.getenv('STRIPE_API_KEY')
```

#### Production Environment

**Set environment variables on server:**

**Heroku:**
```bash
heroku config:set AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
heroku config:set AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**AWS Elastic Beanstalk:**
```bash
eb setenv AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE AWS_SECRET_KEY=wJalrXUtnFEMI/...
```

**Docker:**
```bash
docker run -e AWS_ACCESS_KEY=AKIA... -e AWS_SECRET_KEY=wJa... myapp
```

**Docker Compose:**
```yaml
services:
  app:
    environment:
      - AWS_ACCESS_KEY=${AWS_ACCESS_KEY}
      - AWS_SECRET_KEY=${AWS_SECRET_KEY}
    env_file:
      - .env
```

---

### 5. Clean Git History

⚠️ **WARNING**: This is irreversible! Always backup first.

**Full workflow:**

```bash
# 1. Backup repository
git clone --mirror https://github.com/user/repo.git repo-backup.git

# 2. Clone repository for cleaning
git clone --mirror https://github.com/user/repo.git repo.git
cd repo.git

# 3. Preview cleaning (dry-run)
deployguard clean history --path . --findings ../findings.json

# 4. Review what will be cleaned
# Check the preview output carefully!

# 5. Execute cleaning (⚠️ REWRITES HISTORY!)
deployguard clean history --path . --findings ../findings.json --execute

# 6. Verify secrets are removed
deployguard verify --path . --original-findings ../findings.json

# 7. Push to remote (⚠️ FORCE PUSH!)
git push --force --all
git push --force --tags
```

**Coordinate with team:**

1. **Notify team members** before force pushing
2. **All team members must:**
   ```bash
   # Backup local work
   git stash
   
   # Delete local repo
   cd ..
   rm -rf repo
   
   # Re-clone fresh copy
   git clone https://github.com/user/repo.git
   ```

---

### 6. Rotate Secrets

After cleaning git history, **all exposed secrets must be rotated** (changed).

#### AWS Access Keys

```bash
# 1. Create new access key in AWS Console
# 2. Update .env with new key
# 3. Update production environment
# 4. Delete old access key in AWS Console
```

#### Database Passwords

```sql
-- Connect to database
-- Change password
ALTER USER myuser WITH PASSWORD 'NewS3cr3tP@ssw0rd!';

-- Update .env
DB_PASSWORD=NewS3cr3tP@ssw0rd!

-- Update production
heroku config:set DB_PASSWORD=NewS3cr3tP@ssw0rd!
```

#### API Keys

**Stripe:**
1. Go to Stripe Dashboard → Developers → API Keys
2. Click "Reveal test key token" → "Roll key"
3. Update .env and production environment

**SendGrid:**
1. Go to SendGrid → Settings → API Keys
2. Delete old key, create new key
3. Update .env and production environment

#### OAuth Tokens

**GitHub Personal Access Token:**
1. Go to GitHub → Settings → Developer settings → Personal access tokens
2. Delete old token
3. Generate new token
4. Update .env and production environment

---

### 7. Verify & Test

#### Verify Git History is Clean

```bash
deployguard verify --path . --original-findings findings.json
```

**Expected output:**
```json
{
  "status": "clean",
  "secrets_found": 0,
  "original_secrets": 15,
  "removed": 15,
  "remaining": 0
}
```

#### Test Application

**Local testing:**
```bash
# Load .env
source .env  # or use direnv, dotenv, etc.

# Run application
npm start
# or
python app.py

# Test all features
# - Database connection
# - API integrations
# - Authentication
# - External services
```

**Production testing:**
```bash
# Deploy to staging
git push staging main

# Run smoke tests
curl https://staging.myapp.com/health

# If successful, deploy to production
git push production main
```

---

## Language-Specific Guides

### JavaScript / TypeScript / Node.js

#### Before (Hardcoded):
```javascript
// config/aws.js
const AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

const s3 = new AWS.S3({
  accessKeyId: AWS_ACCESS_KEY,
  secretAccessKey: AWS_SECRET_KEY
});
```

#### After (Environment Variables):
```javascript
// config/aws.js
require('dotenv').config();

const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY,
  secretAccessKey: process.env.AWS_SECRET_KEY
});
```

**.env:**
```env
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Install dotenv:**
```bash
npm install dotenv
```

---

### Python

#### Before (Hardcoded):
```python
# config/database.py
DB_PASSWORD = 'MyS3cr3tP@ssw0rd!'
DATABASE_URL = f'postgresql://user:{DB_PASSWORD}@localhost/mydb'

conn = psycopg2.connect(DATABASE_URL)
```

#### After (Environment Variables):
```python
# config/database.py
import os
from dotenv import load_dotenv

load_dotenv()

DB_PASSWORD = os.getenv('DB_PASSWORD')
DATABASE_URL = f'postgresql://user:{DB_PASSWORD}@localhost/mydb'

conn = psycopg2.connect(DATABASE_URL)
```

**.env:**
```env
DB_PASSWORD=MyS3cr3tP@ssw0rd!
```

**Install python-dotenv:**
```bash
pip install python-dotenv
```

---

### Java

#### Before (Hardcoded):
```java
// src/main/java/config/DatabaseConfig.java
public class DatabaseConfig {
    private static final String DB_PASSWORD = "MyS3cr3tP@ssw0rd!";
    
    public static Connection getConnection() {
        return DriverManager.getConnection(
            "jdbc:postgresql://localhost/mydb",
            "user",
            DB_PASSWORD
        );
    }
}
```

#### After (Environment Variables):
```java
// src/main/java/config/DatabaseConfig.java
public class DatabaseConfig {
    private static final String DB_PASSWORD = System.getenv("DB_PASSWORD");
    
    public static Connection getConnection() {
        return DriverManager.getConnection(
            "jdbc:postgresql://localhost/mydb",
            "user",
            DB_PASSWORD
        );
    }
}
```

**Set environment variable:**
```bash
export DB_PASSWORD='MyS3cr3tP@ssw0rd!'
java -jar app.jar
```

**Or use application.properties:**
```properties
# src/main/resources/application.properties
db.password=${DB_PASSWORD}
```

---

### Go

#### Before (Hardcoded):
```go
// config/aws.go
package config

const (
    AwsAccessKey = "AKIAIOSFODNN7EXAMPLE"
    AwsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

func NewS3Client() *s3.Client {
    return s3.New(AwsAccessKey, AwsSecretKey)
}
```

#### After (Environment Variables):
```go
// config/aws.go
package config

import "os"

func NewS3Client() *s3.Client {
    accessKey := os.Getenv("AWS_ACCESS_KEY")
    secretKey := os.Getenv("AWS_SECRET_KEY")
    return s3.New(accessKey, secretKey)
}
```

**Load .env (using godotenv):**
```go
import "github.com/joho/godotenv"

func init() {
    godotenv.Load()
}
```

---

### Ruby

#### Before (Hardcoded):
```ruby
# config/database.rb
DB_PASSWORD = 'MyS3cr3tP@ssw0rd!'

ActiveRecord::Base.establish_connection(
  adapter: 'postgresql',
  host: 'localhost',
  username: 'user',
  password: DB_PASSWORD,
  database: 'mydb'
)
```

#### After (Environment Variables):
```ruby
# config/database.rb
require 'dotenv/load'

DB_PASSWORD = ENV['DB_PASSWORD']

ActiveRecord::Base.establish_connection(
  adapter: 'postgresql',
  host: 'localhost',
  username: 'user',
  password: DB_PASSWORD,
  database: 'mydb'
)
```

**Install dotenv:**
```bash
gem install dotenv
```

---

### PHP

#### Before (Hardcoded):
```php
// config/database.php
<?php
define('DB_PASSWORD', 'MyS3cr3tP@ssw0rd!');

$conn = new PDO(
    'mysql:host=localhost;dbname=mydb',
    'user',
    DB_PASSWORD
);
```

#### After (Environment Variables):
```php
// config/database.php
<?php
$dbPassword = getenv('DB_PASSWORD');

$conn = new PDO(
    'mysql:host=localhost;dbname=mydb',
    'user',
    $dbPassword
);
```

**Use vlucas/phpdotenv:**
```bash
composer require vlucas/phpdotenv
```

```php
<?php
require 'vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

$dbPassword = $_ENV['DB_PASSWORD'];
```

---

### C#

#### Before (Hardcoded):
```csharp
// Config/DatabaseConfig.cs
public class DatabaseConfig
{
    private const string DbPassword = "MyS3cr3tP@ssw0rd!";
    
    public static SqlConnection GetConnection()
    {
        return new SqlConnection(
            $"Server=localhost;Database=mydb;User=sa;Password={DbPassword};"
        );
    }
}
```

#### After (Environment Variables):
```csharp
// Config/DatabaseConfig.cs
using System;

public class DatabaseConfig
{
    private static string DbPassword => Environment.GetEnvironmentVariable("DB_PASSWORD");
    
    public static SqlConnection GetConnection()
    {
        return new SqlConnection(
            $"Server=localhost;Database=mydb;User=sa;Password={DbPassword};"
        );
    }
}
```

**Or use appsettings.json + User Secrets:**

**appsettings.json:**
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=mydb;User=sa;Password={0};"
  }
}
```

**User Secrets:**
```bash
dotnet user-secrets set "DbPassword" "MyS3cr3tP@ssw0rd!"
```

---

## CI/CD Integration

### GitHub Actions Secrets

#### 1. Add Secrets to GitHub

**Via Web UI:**
1. Go to repository → Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Add each secret:
   - Name: `AWS_ACCESS_KEY`
   - Value: `AKIAIOSFODNN7EXAMPLE`

**Via GitHub CLI:**
```bash
# Install GitHub CLI
brew install gh

# Login
gh auth login

# Add secrets
echo "AKIAIOSFODNN7EXAMPLE" | gh secret set AWS_ACCESS_KEY --repo user/repo
echo "wJalrXUtnFEMI/..." | gh secret set AWS_SECRET_KEY --repo user/repo
echo "MyS3cr3tP@ssw0rd!" | gh secret set DB_PASSWORD --repo user/repo
```

**Automated script (generated by DeployGuard):**
```bash
deployguard remediate github-secrets --findings findings.json --repo user/repo
# Generates: setup-secrets.sh

chmod +x setup-secrets.sh
./setup-secrets.sh
```

#### 2. Use Secrets in Workflow

**.github/workflows/deploy.yml:**
```yaml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Deploy to production
        env:
          AWS_ACCESS_KEY: ${{ secrets.AWS_ACCESS_KEY }}
          AWS_SECRET_KEY: ${{ secrets.AWS_SECRET_KEY }}
          DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
        run: |
          npm install
          npm run build
          npm run deploy
```

---

### GitLab CI/CD

**Add variables in GitLab:**
1. Go to Project → Settings → CI/CD → Variables
2. Add each variable:
   - Key: `AWS_ACCESS_KEY`
   - Value: `AKIAIOSFODNN7EXAMPLE`
   - Protected: ✅
   - Masked: ✅

**.gitlab-ci.yml:**
```yaml
deploy:
  stage: deploy
  script:
    - npm install
    - npm run build
    - npm run deploy
  variables:
    AWS_ACCESS_KEY: $AWS_ACCESS_KEY
    AWS_SECRET_KEY: $AWS_SECRET_KEY
  only:
    - main
```

---

### Jenkins

**Add credentials in Jenkins:**
1. Jenkins → Manage Jenkins → Manage Credentials
2. Add → Secret text
3. Secret: `AKIAIOSFODNN7EXAMPLE`
4. ID: `aws-access-key`

**Jenkinsfile:**
```groovy
pipeline {
    agent any
    
    environment {
        AWS_ACCESS_KEY = credentials('aws-access-key')
        AWS_SECRET_KEY = credentials('aws-secret-key')
        DB_PASSWORD = credentials('db-password')
    }
    
    stages {
        stage('Deploy') {
            steps {
                sh 'npm install'
                sh 'npm run build'
                sh 'npm run deploy'
            }
        }
    }
}
```

---

## Best Practices

### 1. Never Commit Secrets

**Add to .gitignore:**
```gitignore
# Environment files
.env
.env.local
.env.production
.env.*.local

# Secret files
secrets.yml
secrets.json
config/secrets.json

# Private keys
*.pem
*.key
id_rsa
id_ed25519
```

### 2. Use Environment-Specific Configs

**Development (.env.development):**
```env
DB_HOST=localhost
DB_PASSWORD=dev_password
STRIPE_API_KEY=sk_test_...
```

**Production (.env.production):**
```env
DB_HOST=prod.database.com
DB_PASSWORD=pr0d_p@ssw0rd!
STRIPE_API_KEY=sk_live_...
```

### 3. Use Secret Management Systems

**AWS Secrets Manager:**
```javascript
const AWS = require('aws-sdk');
const secretsManager = new AWS.SecretsManager();

async function getSecret(secretName) {
  const data = await secretsManager.getSecretValue({ SecretId: secretName }).promise();
  return JSON.parse(data.SecretString);
}

const dbPassword = await getSecret('prod/db/password');
```

**HashiCorp Vault:**
```bash
vault kv get secret/database/password
```

**Azure Key Vault:**
```csharp
var client = new SecretClient(new Uri(vaultUri), new DefaultAzureCredential());
KeyVaultSecret secret = await client.GetSecretAsync("DbPassword");
string dbPassword = secret.Value;
```

### 4. Rotate Secrets Regularly

- Change passwords every 90 days
- Rotate API keys every 6 months
- Use short-lived tokens when possible
- Implement automatic rotation where supported

### 5. Use Pre-Commit Hooks

**Install hook:**
```bash
deployguard hooks install --strict
```

**Manual setup (.git/hooks/pre-commit):**
```bash
#!/bin/bash
deployguard scan local --path . --severity high

if [ $? -ne 0 ]; then
  echo "❌ Secrets detected! Commit blocked."
  exit 1
fi
```

---

## Common Scenarios

### Scenario 1: AWS Credentials

**Before:**
```javascript
const AWS = require('aws-sdk');

const s3 = new AWS.S3({
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  region: 'us-east-1'
});
```

**After:**
```javascript
require('dotenv').config();
const AWS = require('aws-sdk');

const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY,
  secretAccessKey: process.env.AWS_SECRET_KEY,
  region: process.env.AWS_REGION || 'us-east-1'
});
```

**.env:**
```env
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1
```

**Rotate:**
1. Create new IAM access key in AWS Console
2. Update .env and GitHub Secrets
3. Delete old access key

---

### Scenario 2: Database Connection String

**Before:**
```python
import psycopg2

conn = psycopg2.connect(
    "postgresql://admin:MyS3cr3tP@ssw0rd!@localhost:5432/mydb"
)
```

**After:**
```python
import os
from dotenv import load_dotenv
import psycopg2

load_dotenv()

DATABASE_URL = os.getenv('DATABASE_URL')
conn = psycopg2.connect(DATABASE_URL)
```

**.env:**
```env
DATABASE_URL=postgresql://admin:MyS3cr3tP@ssw0rd!@localhost:5432/mydb
```

**Or separate components:**
```env
DB_HOST=localhost
DB_PORT=5432
DB_NAME=mydb
DB_USER=admin
DB_PASSWORD=MyS3cr3tP@ssw0rd!
```

```python
DATABASE_URL = f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
```

**Rotate:**
```sql
ALTER USER admin WITH PASSWORD 'N3wP@ssw0rd!2024';
```

---

### Scenario 3: API Keys

**Before:**
```javascript
const stripe = require('stripe')('sk_test_51HxKJ2eZvKY3qBdz...');
```

**After:**
```javascript
require('dotenv').config();
const stripe = require('stripe')(process.env.STRIPE_API_KEY);
```

**.env:**
```env
STRIPE_API_KEY=sk_test_51HxKJ2eZvKY3qBdz...
```

**Rotate:**
1. Stripe Dashboard → Developers → API Keys
2. Roll key
3. Update .env and production

---

### Scenario 4: JWT Secret

**Before:**
```javascript
const jwt = require('jsonwebtoken');

const token = jwt.sign({ userId: 123 }, 'my-super-secret-jwt-key');
```

**After:**
```javascript
require('dotenv').config();
const jwt = require('jsonwebtoken');

const token = jwt.sign({ userId: 123 }, process.env.JWT_SECRET);
```

**.env:**
```env
JWT_SECRET=my-super-secret-jwt-key-2024
```

**Generate strong secret:**
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

---

## Troubleshooting

### Issue: Environment Variables Not Loading

**Solution:**
```javascript
// Add at the very top of your entry file
require('dotenv').config();

// Debug
console.log('AWS_ACCESS_KEY:', process.env.AWS_ACCESS_KEY);
```

### Issue: Git History Still Shows Secrets

**Solution:**
```bash
# Verify cleaning was successful
deployguard verify --path .

# If secrets still found, re-run cleaning
deployguard clean history --path . --findings findings.json --execute --force

# Force push again
git push --force --all
git push --force --tags
```

### Issue: Application Breaks After Remediation

**Solution:**
1. Check all environment variables are set
2. Verify .env file exists and is loaded
3. Check production environment has all secrets configured
4. Review code changes for typos
5. Test locally first, then staging, then production

---

## Quick Reference

### Remediation Checklist

- [ ] Scan repository for secrets
- [ ] Extract secrets to .env.example
- [ ] Create .env with real values
- [ ] Add .env to .gitignore
- [ ] Update code to use environment variables
- [ ] Test locally
- [ ] Configure production environment (Heroku, AWS, etc.)
- [ ] Add secrets to GitHub Actions / CI/CD
- [ ] Clean git history
- [ ] Force push to remote
- [ ] Coordinate with team to re-clone
- [ ] Rotate all exposed secrets
- [ ] Verify secrets are removed
- [ ] Test in production
- [ ] Install pre-commit hooks
- [ ] Document new environment variable requirements

---

**Need help?** See [README.md](README.md) or [CLI_REFERENCE.md](CLI_REFERENCE.md)
