#!/usr/bin/env python3
"""
Quick script to export secrets from the already-scanned repository.
"""

import sys
import os
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from deployguard.core.history_cleaner import GitHistoryCleaner
from deployguard.core.scanner import SecretScanner

REPO_PATH = "/Users/salginci/Source/GITHUB/deployguard_test_repo"
OUTPUT_DIR = "/Users/salginci/Source/GITHUB/deployguard_test_repo_secrets_export"

def main():
    print("=" * 70)
    print("🔐 DeployGuard Secrets Export")
    print("=" * 70)
    print()
    
    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Initialize and scan
    print("🔧 Initializing...")
    scanner = SecretScanner()
    cleaner = GitHistoryCleaner(scanner)
    
    print("📍 Scanning secrets (this takes ~15 min for 1559 commits)...")
    secrets = cleaner.scan_git_history(REPO_PATH, include_all_branches=True)
    
    print(f"   Found {len(secrets)} secrets")
    print()
    
    repo_name = os.path.basename(REPO_PATH)
    
    # 1. Export to JSON
    print("📄 Exporting to JSON...")
    json_path = os.path.join(OUTPUT_DIR, f"{repo_name}_secrets.json")
    data = {
        "repository": repo_name,
        "exported_at": datetime.now().isoformat(),
        "total_secrets": len(secrets),
        "secrets": []
    }
    for secret in secrets:
        data["secrets"].append({
            "env_var": secret.suggested_env_var,
            "value": secret.value,
            "type": secret.secret_type,
            "severity": secret.severity,
            "files": secret.files[:5],
            "commit_count": len(secret.commits),
        })
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"   ✅ {json_path}")
    
    # 2. Export to .env format
    print("📄 Exporting to .env format...")
    env_path = os.path.join(OUTPUT_DIR, f"{repo_name}_secrets.env")
    seen_vars = set()
    with open(env_path, "w", encoding="utf-8") as f:
        f.write(f"# DeployGuard Secrets Export\n")
        f.write(f"# Repository: {repo_name}\n")
        f.write(f"# Exported: {datetime.now().isoformat()}\n")
        f.write(f"# Total secrets: {len(secrets)}\n")
        f.write(f"#\n")
        f.write(f"# ⚠️  WARNING: This file contains sensitive data!\n")
        f.write(f"# ⚠️  Do NOT commit this file to git!\n")
        f.write(f"\n")
        
        for secret in secrets:
            var_name = secret.suggested_env_var
            if var_name in seen_vars:
                counter = 1
                while f"{var_name}_{counter}" in seen_vars:
                    counter += 1
                var_name = f"{var_name}_{counter}"
            seen_vars.add(var_name)
            
            value = secret.value.replace("'", "'\\''")
            f.write(f"# Type: {secret.secret_type} | Severity: {secret.severity}\n")
            f.write(f"{var_name}='{value}'\n\n")
    print(f"   ✅ {env_path}")
    
    # 3. Export GitHub CLI script
    print("📄 Exporting GitHub CLI script...")
    gh_script_path = os.path.join(OUTPUT_DIR, f"{repo_name}_set_github_secrets.sh")
    seen_vars = set()
    with open(gh_script_path, "w", encoding="utf-8") as f:
        f.write("#!/bin/bash\n")
        f.write(f"# DeployGuard - Set GitHub Secrets\n")
        f.write(f"# Repository: {repo_name}\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n")
        f.write(f"#\n")
        f.write(f"# Prerequisites:\n")
        f.write(f"#   1. Install GitHub CLI: brew install gh\n")
        f.write(f"#   2. Authenticate: gh auth login\n")
        f.write(f"#   3. Set REPO variable below\n")
        f.write(f"#   4. Run: bash {os.path.basename(gh_script_path)}\n")
        f.write(f"#\n")
        f.write(f"# For GitHub Environments, add: --env ENVIRONMENT_NAME\n")
        f.write(f"\n")
        f.write(f"set -e\n\n")
        f.write(f"REPO=\"OWNER/REPO\"  # TODO: Set your GitHub repo here!\n")
        f.write(f"\n")
        f.write(f"echo \"Setting secrets for $REPO...\"\n")
        f.write(f"\n")
        
        for secret in secrets:
            var_name = secret.suggested_env_var
            var_name = ''.join(c if c.isalnum() or c == '_' else '_' for c in var_name)
            var_name = var_name.upper()
            
            if var_name in seen_vars:
                counter = 1
                while f"{var_name}_{counter}" in seen_vars:
                    counter += 1
                var_name = f"{var_name}_{counter}"
            seen_vars.add(var_name)
            
            value = secret.value.replace("'", "'\\''")
            f.write(f"# {secret.secret_type} ({secret.severity})\n")
            f.write(f"echo '{value}' | gh secret set {var_name} --repo \"$REPO\"\n\n")
        
        f.write(f"\necho \"✅ All {len(secrets)} secrets have been set!\"\n")
    os.chmod(gh_script_path, 0o755)
    print(f"   ✅ {gh_script_path}")
    
    # 4. Summary by severity
    print()
    print("=" * 70)
    print("📊 EXPORT SUMMARY")
    print("=" * 70)
    
    from collections import Counter
    severities = Counter(s.severity for s in secrets)
    types = Counter(s.secret_type for s in secrets)
    
    print()
    print("By Severity:")
    for sev in ["critical", "high", "medium", "low"]:
        if sev in severities:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[sev]
            print(f"   {emoji} {sev.upper()}: {severities[sev]}")
    
    print()
    print("Top Secret Types:")
    for typ, count in types.most_common(10):
        print(f"   • {typ}: {count}")
    
    print()
    print("📁 All exports saved to:")
    print(f"   {OUTPUT_DIR}")
    print()
    print("📋 Files created:")
    for f in os.listdir(OUTPUT_DIR):
        size = os.path.getsize(os.path.join(OUTPUT_DIR, f))
        print(f"   • {f} ({size/1024:.1f} KB)")

if __name__ == "__main__":
    main()
