# 🛡️ DeployGuard: Complete Secrets Cleanup Workflow

A step-by-step guide to detect, review, clean, and migrate secrets from your repository to a new GitHub repository.

---

## 📋 Overview

This workflow guides you through:

| Step | Description |
|------|-------------|
| 1️⃣ | Clone repository as a mirror (preserves all branches) |
| 2️⃣ | Scan all branches for secrets with interactive review |
| 3️⃣ | User confirms which detections are actual secrets |
| 4️⃣ | Clean selected secrets from git history |
| 5️⃣ | Push secrets to new GitHub repository (automated) |
| 6️⃣ | Push cleaned repository to new GitHub target |
| 7️⃣ | Generate comprehensive reports |

> ⚠️ **IMPORTANT**: Always work on a **mirror clone**, never on your original repository!

---

## 🔧 Prerequisites

### Install DeployGuard

```bash
pip install deployguard-repo-guard
```

Or from source:

```bash
git clone https://github.com/salginci/deployguard_repository_cleaner.git
cd deployguard_repository_cleaner
pip install -e .
```

### Required Tools

```bash
# Verify git is installed
git --version

# Install git-filter-repo (recommended for faster history rewriting)
pip install git-filter-repo

# For pushing secrets to GitHub (optional)
pip install PyNaCl requests
```

### GitHub Token (for automated secret pushing)

Create a Personal Access Token with these scopes:
- `repo` (full control)
- `admin:repo_hook` (for environments)

```bash
export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxx"
```

---

## Step 1️⃣: Clone Repository as Mirror

Create a mirror clone that preserves ALL branches, tags, and history:

```bash
# Clone with --mirror flag
git clone --mirror https://github.com/your-org/your-repo.git your-repo.git

# Navigate to the mirror directory
cd your-repo.git

# Verify all branches are present
git branch -a
```

> 💡 **Why mirror?** A mirror clone is a bare repository that contains:
> - All branches (local and remote tracking)
> - All tags
> - Complete git history
> - All refs

---

## Step 2️⃣: Scan All Branches for Secrets

Run the interactive scan that covers ALL branches:

### Option A: Interactive Mode (Recommended)

```bash
deployguard clean history --path . --dry-run --use-env-vars
```

This will:
1. Scan ALL commits across ALL branches
2. Detect secrets using 961+ patterns
3. Show you each detected item for review
4. Provide false positive hints

### Option B: Scan First, Review Later

```bash
# First, just scan and export findings
deployguard scan history --path . --output secrets_scan.json

# Review the JSON report
cat secrets_scan.json
```

### Expected Output

```
🧹 DeployGuard History Cleaner
============================================================

🔍 Scanning git history for secrets...
   Found 847 commits to scan...
   Progress: 100/847 commits (5 secrets found)
   Progress: 200/847 commits (12 secrets found)
   ...
   Found 23 unique secrets

============================================================
🔍 INTERACTIVE SECRET REVIEW
============================================================

⚠️  Review each detected item carefully!
   Some detections may be FALSE POSITIVES (code, URLs, etc.)
   Only select items that are ACTUAL SECRETS.
```

---

## Step 3️⃣: Interactive Secret Evaluation

For each detected item, you'll see:

```
------------------------------------------------------------
[1/23] database_password (high)
   📄 Value: Password123***
   🏷️  Env Var: DG_DATABASE_PASSWORD
   ➡️  Will replace with: ${DG_DATABASE_PASSWORD}
   📁 Found in 3 file(s): appsettings.json, config.yml, web.config
   📜 In 15 commit(s)
   ⚠️  POSSIBLE FALSE POSITIVE: None detected

   Include in cleanup? [y/n/a/s/q]:
```

### Commands

| Key | Action | Use When |
|-----|--------|----------|
| `y` | **Yes** - Add to cleanup list | This IS an actual secret that should be removed |
| `n` | **No** - Skip this item | This is a FALSE POSITIVE (sample value, test data, etc.) |
| `a` | **All** - Accept all remaining | You're confident remaining items are all secrets |
| `s` | **Skip All** - Skip all remaining | Remaining items are all false positives |
| `q` | **Quit** - Cancel operation | You want to stop and review later |

### False Positive Detection

DeployGuard automatically provides hints for common false positives:

```
⚠️  POSSIBLE FALSE POSITIVE: SSL Certificate Pin (public key hash) - NOT a secret, safe to keep
⚠️  POSSIBLE FALSE POSITIVE: Looks like a documentation/schema URL - NOT a secret
⚠️  POSSIBLE FALSE POSITIVE: Android XML namespace - NOT a secret
```

### Selection Summary

After reviewing all items:

```
============================================================
📊 Selection Summary:
   ✅ Selected for cleanup: 18
   ⏭️  Skipped (false positives): 5

📁 Feedback saved locally: ~/.deployguard/feedback/feedback_20260316_143022.json
```

> 💡 Your feedback is anonymized and helps improve detection accuracy!

---

## Step 4️⃣: Execute Secret Cleanup

After reviewing, execute the cleanup:

```bash
# Execute the cleanup (replaces secrets with environment variables)
deployguard clean history --path . --execute --use-env-vars
```

### What Happens

1. **Secrets Replaced**: Each confirmed secret is replaced with `${ENV_VAR_NAME}`
2. **History Rewritten**: All commits containing secrets are rewritten
3. **Files Generated**:
   - `secrets_to_purge.txt` - List of secrets that were cleaned
   - `.env.template` - Template for environment variables
   - `cleanup_report.json` - Detailed cleanup report

### Alternative: Use Placeholder

If you prefer `***REMOVED***` instead of environment variables:

```bash
deployguard clean history --path . --execute --use-placeholder
```

### Generated Files

After cleanup, you'll find these files in the parent directory:

```
../
├── secrets_to_purge.txt     # BFG-compatible format
├── .env.template            # Environment variable template
├── cleanup_report.json      # Detailed JSON report
└── your-repo.git/           # Your cleaned mirror
```

---

## Step 5️⃣: Push Secrets to New GitHub Repository

Automatically push the detected secrets to your new GitHub repository as GitHub Secrets:

### Prepare Secrets File

After cleanup, a secrets file is generated. You can also create one manually:

```bash
# Export detected secrets with their values
deployguard scan history --path . --export-secrets secrets_with_values.json
```

### Push to GitHub Repository Secrets

```bash
# Set your GitHub token
export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxx"

# Push secrets to repository
python push_secrets_to_github.py \
    --repo your-org/new-repo \
    --secrets-file secrets_with_values.json
```

### Push to GitHub Environment Secrets (Recommended for Production)

```bash
# Push to specific environment (production, staging, etc.)
python push_secrets_to_github.py \
    --repo your-org/new-repo \
    --secrets-file secrets_with_values.json \
    --environment production
```

### Expected Output

```
🔐 GitHub Secrets Manager
============================================================

📦 Repository: your-org/new-repo
🔑 Secrets to push: 18

Pushing secrets...
  ✅ DG_DATABASE_PASSWORD
  ✅ DG_JWT_SECRET_KEY
  ✅ DG_FCM_SERVER_KEY
  ✅ DG_RABBITMQ_PASSWORD
  ...

============================================================
✅ Successfully pushed 18/18 secrets to your-org/new-repo
```

---

## Step 6️⃣: Push Cleaned Repository to New GitHub

### Create New Target Repository

```bash
# Create new repository on GitHub (via UI or CLI)
gh repo create your-org/new-repo --private

# Or use the GitHub API
curl -X POST -H "Authorization: token $GITHUB_TOKEN" \
  -d '{"name":"new-repo","private":true}' \
  https://api.github.com/orgs/your-org/repos
```

### Push Cleaned Mirror

```bash
# Add new remote
cd your-repo.git
git remote add new-origin https://github.com/your-org/new-repo.git

# Push ALL branches and tags to new repository
git push --mirror new-origin
```

### Alternative: Push to Existing Repository (Force)

> ⚠️ **DANGER**: This will OVERWRITE the target repository!

```bash
# Only if you're replacing an existing repository
git push --mirror --force new-origin
```

---

## Step 7️⃣: Generate Reports

### Generate Multi-Format Reports

```bash
# Generate comprehensive reports
deployguard scan history --path . \
    --output report \
    --format all
```

This generates:

| File | Description |
|------|-------------|
| `report.json` | Machine-readable JSON with all findings |
| `report.csv` | Spreadsheet-compatible CSV |
| `report.html` | Interactive HTML report |
| `report.md` | Markdown summary |

### Generate Turkish-Style Audit Reports

```bash
# Generate 5-part Turkish audit reports
deployguard scan history --path . \
    --multi-report \
    --report-dir ./reports
```

Generates:

```
reports/
├── your-repo_01_overview.md      # Executive summary
├── your-repo_02_history.md       # Commit/branch history analysis
├── your-repo_03_variables.md     # Environment variable definitions
├── your-repo_04_remediation.md   # Cleanup changes report
└── your-repo_05_summary.md       # Final status and recommendations
```

### View Report Stats

```bash
# Show statistics from a JSON report
deployguard report stats cleanup_report.json

# Show findings filtered by severity
deployguard report show cleanup_report.json --severity critical
```

---

## 🔄 Complete Workflow Script

For convenience, here's a complete script:

```bash
#!/bin/bash
set -e

# Configuration
ORIGINAL_REPO="https://github.com/your-org/original-repo.git"
NEW_REPO="your-org/new-repo"
WORK_DIR="./cleanup-work"
GITHUB_TOKEN="${GITHUB_TOKEN}"  # Set this environment variable

echo "🛡️ DeployGuard Complete Cleanup Workflow"
echo "========================================"

# Step 1: Clone mirror
echo "📥 Step 1: Cloning repository as mirror..."
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"
git clone --mirror "$ORIGINAL_REPO" repo.git
cd repo.git

# Step 2 & 3: Scan and interactive review
echo "🔍 Step 2-3: Scanning and reviewing secrets..."
deployguard clean history --path . --dry-run --use-env-vars

# Ask user to proceed
read -p "Ready to execute cleanup? (y/n): " proceed
if [ "$proceed" != "y" ]; then
    echo "Aborted."
    exit 1
fi

# Step 4: Execute cleanup
echo "🧹 Step 4: Executing cleanup..."
deployguard clean history --path . --execute --use-env-vars

# Step 5: Push secrets to GitHub
echo "🔐 Step 5: Pushing secrets to new GitHub repository..."
cd ..
python push_secrets_to_github.py \
    --repo "$NEW_REPO" \
    --secrets-file ./secrets_with_values.json \
    --environment production

# Step 6: Push cleaned repo
echo "📤 Step 6: Pushing cleaned repository..."
cd repo.git
git remote add new-origin "https://github.com/$NEW_REPO.git"
git push --mirror new-origin

# Step 7: Generate reports
echo "📊 Step 7: Generating reports..."
cd ..
mkdir -p reports
deployguard report stats repo.git/cleanup_report.json

echo ""
echo "✅ Workflow Complete!"
echo "========================================"
echo "📦 New repository: https://github.com/$NEW_REPO"
echo "🔐 Secrets pushed: See GitHub Settings > Secrets"
echo "📄 Reports: ./reports/"
```

---

## 📝 Post-Cleanup Checklist

### Required Actions

- [ ] **Rotate ALL detected secrets** - Even though they're removed from git, they may still be compromised
- [ ] **Update application configuration** - Use environment variables instead of hardcoded values
- [ ] **Notify team members** - All developers need to re-clone the repository
- [ ] **Delete old repository** - After validation, remove the old repository

### Credential Rotation per Type

| Secret Type | Rotation Instructions |
|-------------|----------------------|
| **Database Passwords** | Change password in database server, update connection strings |
| **API Keys** | Regenerate in provider console, update applications |
| **JWT Secrets** | Generate new key (256-bit), redeploy (users will need to re-login) |
| **FCM Server Keys** | Firebase Console → Regenerate → Update all services |
| **VAPID Keys** | Generate new pair → Push subscriptions need re-registration |
| **OAuth Secrets** | Regenerate in OAuth provider → Update client applications |

### Developer Re-Clone Instructions

Share with your team:

```bash
# Delete old repository
rm -rf old-repo

# Clone fresh copy
git clone https://github.com/your-org/new-repo.git

# Configure environment
cp .env.template .env
# Edit .env with actual secret values
```

---

## 🆘 Troubleshooting

### "Not a git repository"

```bash
# Make sure you're in the .git directory
cd your-repo.git
ls  # Should show HEAD, objects, refs, etc.
```

### "git-filter-repo not found"

```bash
pip install git-filter-repo
```

### "Rate limit exceeded" (GitHub)

Wait 1 hour or use a different token.

### "Permission denied" pushing to new repo

```bash
# Check your token permissions
gh auth status

# Re-authenticate if needed
gh auth login
```

### Some secrets not detected

```bash
# Use custom patterns file
deployguard clean history --path . \
    --patterns-file ./custom_patterns.yaml
```

---

## 📚 Related Documentation

- [CLI Reference](CLI_REFERENCE.md) - All available commands
- [API Documentation](API_DOCUMENTATION.md) - REST API usage
- [Remediation Guide](REMEDIATION_GUIDE.md) - Detailed remediation steps
- [False Positive Reduction](FALSE_POSITIVE_REDUCTION.md) - Reducing false positives

---

## 🤝 Support

If you encounter issues:

1. Check the [Troubleshooting](#troubleshooting) section
2. Review generated reports for details
3. Open an issue on GitHub

---

*Generated by DeployGuard Repository Cleaner*
