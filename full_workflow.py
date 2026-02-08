#!/usr/bin/env python3
"""
DeployGuard Complete Workflow
=============================
1. Analyze repository for secrets and large files
2. Export secrets to usable formats
3. Clean git history
4. Verify cleanup
5. Generate before/after reports
"""

import sys
import os
import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from deployguard.core.scanner import SecretScanner
# Use the FAST parallel cleaner for better performance
from deployguard.core.history_cleaner_fast import FastGitHistoryCleaner as GitHistoryCleaner

# =============================================================================
# CONFIGURATION
# =============================================================================
REPO_PATH = "/Users/salginci/Source/GITHUB/smartcabin_backend"
REPO_NAME = "smartcabin_backend"
OUTPUT_DIR = f"/Users/salginci/Source/GITHUB/{REPO_NAME}_security_audit"
MIRROR_PATH = f"/Users/salginci/Source/GITHUB/{REPO_NAME}_mirror.git"

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def print_header(title: str):
    """Print a formatted header."""
    print()
    print("=" * 70)
    print(f"🔐 {title}")
    print("=" * 70)
    print()

def print_section(title: str):
    """Print a section header."""
    print()
    print(f"{'─' * 50}")
    print(f"📌 {title}")
    print(f"{'─' * 50}")

def run_command(cmd: list, cwd: str = None) -> tuple:
    """Run a shell command and return (success, output)."""
    try:
        result = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True
        )
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as e:
        return False, str(e)

def format_size(size_bytes: int) -> str:
    """Format bytes to human readable."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"

# =============================================================================
# MAIN WORKFLOW
# =============================================================================

def main():
    start_time = datetime.now()
    
    print_header("DeployGuard Complete Security Audit")
    print(f"Repository: {REPO_PATH}")
    print(f"Output: {OUTPUT_DIR}")
    print(f"Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Initialize scanner and cleaner
    scanner = SecretScanner()
    cleaner = GitHistoryCleaner(scanner)
    
    # =========================================================================
    # PHASE 1A: SCAN CURRENT STATE (HEAD) - For GitHub Secrets
    # =========================================================================
    print_header("PHASE 1A: Scanning Current State (HEAD) for Secrets to Save")
    
    print("⏳ Scanning current files for secrets to export as GitHub secrets...")
    print()
    
    # Scan only the current working tree (HEAD) - these are the values we want to SAVE
    current_secrets = {}  # env_var -> secret (keep only latest by env_var name)
    
    for root, dirs, files in os.walk(REPO_PATH):
        # Skip git directory and other non-essential folders
        dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'bin', 'obj', '.vs', 'packages']]
        
        for file_name in files:
            file_path = os.path.join(root, file_name)
            rel_path = os.path.relpath(file_path, REPO_PATH)
            
            # Skip binary and large files
            if any(file_name.endswith(ext) for ext in ['.dll', '.exe', '.png', '.jpg', '.gif', '.ico', '.pdf', '.zip']):
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if len(content) > 500000:  # Skip very large files
                        continue
                    
                findings = scanner.scan_file(rel_path, content)
                for finding in findings:
                    env_var = finding.suggested_variable or f"DG_{finding.type.value if hasattr(finding.type, 'value') else str(finding.type)}"
                    # Keep the secret, using env_var as key to avoid duplicates
                    if env_var not in current_secrets:
                        current_secrets[env_var] = {
                            "env_var": env_var,
                            "value": finding.exposed_value,
                            "type": finding.type.value if hasattr(finding.type, 'value') else str(finding.type),
                            "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                            "file": rel_path,
                        }
            except Exception:
                pass
    
    print(f"✅ Found {len(current_secrets)} unique secrets in current state (HEAD)")
    print("   These will be exported as GitHub Secrets")
    print()
    
    # =========================================================================
    # PHASE 1B: SCAN GIT HISTORY - For Cleanup (ALL historical values)
    # =========================================================================
    print_header("PHASE 1B: Scanning Git History for Secrets to Remove")
    
    print("⏳ This will scan ALL commits to find ALL secret values to remove...")
    print("   (Estimated time: 2-3 minutes for ~1500 commits)")
    print()
    
    secrets_before = cleaner.scan_git_history(
        REPO_PATH, 
        include_all_branches=True,
        show_progress=True
    )
    
    # Count by severity
    severity_counts = Counter(s.severity for s in secrets_before)
    type_counts = Counter(s.secret_type for s in secrets_before)
    
    print()
    print(f"✅ Found {len(secrets_before)} unique secret VALUES in history (to be removed)")
    print()
    print("By Severity:")
    for sev in ["critical", "high", "medium", "low"]:
        if sev in severity_counts:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[sev]
            print(f"   {emoji} {sev.upper()}: {severity_counts[sev]}")
    
    print()
    print("Top Secret Types:")
    for typ, count in type_counts.most_common(10):
        print(f"   • {typ}: {count}")
    
    # =========================================================================
    # PHASE 2: SCAN FOR LARGE FILES
    # =========================================================================
    print_header("PHASE 2: Scanning for Large Files (>100MB)")
    
    large_files = cleaner.scan_large_files(REPO_PATH, max_size_mb=100.0, show_progress=True)
    
    if large_files:
        print(f"✅ Found {len(large_files)} large files:")
        for file_path, size in large_files:
            print(f"   • {file_path}: {format_size(size)}")
    else:
        print("✅ No large files found (all under 100MB)")
    
    # =========================================================================
    # PHASE 3: EXPORT SECRETS
    # =========================================================================
    print_header("PHASE 3: Exporting Secrets")
    
    # Export ALL historical secrets to JSON (for reference/audit)
    json_path = os.path.join(OUTPUT_DIR, f"{REPO_NAME}_secrets_HISTORY.json")
    export_data = {
        "repository": REPO_NAME,
        "scan_date": datetime.now().isoformat(),
        "description": "ALL secret values found in git history (for removal)",
        "total_secrets": len(secrets_before),
        "by_severity": dict(severity_counts),
        "by_type": dict(type_counts),
        "secrets": []
    }
    
    for secret in secrets_before:
        export_data["secrets"].append({
            "env_var": secret.suggested_env_var,
            "value": secret.value,
            "type": secret.secret_type,
            "severity": secret.severity,
            "files": secret.files[:5],
            "commit_count": len(secret.commits),
        })
    
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)
    print(f"✅ Historical Secrets JSON (for audit): {json_path}")
    
    # Export CURRENT STATE secrets to JSON (for GitHub Secrets)
    current_json_path = os.path.join(OUTPUT_DIR, f"{REPO_NAME}_secrets_CURRENT.json")
    current_export_data = {
        "repository": REPO_NAME,
        "scan_date": datetime.now().isoformat(),
        "description": "CURRENT secret values from HEAD (for GitHub Secrets)",
        "total_secrets": len(current_secrets),
        "secrets": list(current_secrets.values())
    }
    
    with open(current_json_path, "w", encoding="utf-8") as f:
        json.dump(current_export_data, f, indent=2, ensure_ascii=False)
    print(f"✅ Current Secrets JSON (for GitHub): {current_json_path}")
    
    # Export CURRENT STATE to .env format (for local dev)
    env_path = os.path.join(OUTPUT_DIR, f"{REPO_NAME}_secrets.env")
    with open(env_path, "w", encoding="utf-8") as f:
        f.write(f"# DeployGuard Secrets Export - CURRENT STATE ONLY\n")
        f.write(f"# Repository: {REPO_NAME}\n")
        f.write(f"# Exported: {datetime.now().isoformat()}\n")
        f.write(f"# Total: {len(current_secrets)} secrets from HEAD\n")
        f.write(f"# ⚠️  WARNING: Contains sensitive data!\n")
        f.write(f"# NOTE: Only current values, not historical ones\n\n")
        
        for env_var, secret in current_secrets.items():
            var_name = ''.join(c if c.isalnum() or c == '_' else '_' for c in env_var)
            value = secret['value'].replace("'", "'\\''")
            f.write(f"# {secret['type']} ({secret['severity']}) - {secret['file']}\n")
            f.write(f"{var_name}='{value}'\n\n")
    print(f"✅ Secrets ENV (current state): {env_path}")
    
    # Export GitHub CLI script - CURRENT STATE only
    gh_script_path = os.path.join(OUTPUT_DIR, f"{REPO_NAME}_set_github_secrets.sh")
    with open(gh_script_path, "w", encoding="utf-8") as f:
        f.write("#!/bin/bash\n")
        f.write(f"# DeployGuard - GitHub Secrets Setup (CURRENT STATE ONLY)\n")
        f.write(f"# Repository: {REPO_NAME}\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n")
        f.write(f"# Total: {len(current_secrets)} secrets\n")
        f.write(f"# NOTE: Only current values from HEAD, not historical duplicates\n\n")
        f.write(f"set -e\n\n")
        f.write(f"REPO=\"OWNER/REPO\"  # TODO: Set your repo!\n\n")
        
        for env_var, secret in current_secrets.items():
            if secret['severity'] in ["critical", "high"]:
                var_name = ''.join(c if c.isalnum() or c == '_' else '_' for c in env_var).upper()
                value = secret['value'].replace("'", "'\\''")
                f.write(f"# {secret['type']} - {secret['file']}\n")
                f.write(f"echo '{value}' | gh secret set {var_name} --repo \"$REPO\"\n\n")
    os.chmod(gh_script_path, 0o755)
    print(f"✅ GitHub CLI Script (current state): {gh_script_path}")
    
    # =========================================================================
    # PHASE 4: CREATE MIRROR AND CLEAN
    # =========================================================================
    print_header("PHASE 4: Creating Mirror and Cleaning Git History")
    
    # Remove old mirror if exists
    if os.path.exists(MIRROR_PATH):
        print(f"🗑️  Removing old mirror...")
        shutil.rmtree(MIRROR_PATH)
    
    # Create mirror clone
    print(f"📦 Creating mirror clone...")
    success, output = run_command(
        ["git", "clone", "--mirror", REPO_PATH, MIRROR_PATH]
    )
    if not success:
        print(f"❌ Failed to create mirror: {output}")
        return
    print(f"✅ Mirror created: {MIRROR_PATH}")
    
    # Run cleanup
    print()
    print("🧹 Running cleanup (this may take several minutes)...")
    print()
    
    cleanup_result = cleaner.full_cleanup(
        MIRROR_PATH,
        secrets=secrets_before,
        large_files=large_files,
        dry_run=False,  # Actually perform the cleanup!
        show_progress=True,
    )
    
    print()
    print("📊 Cleanup Results:")
    print(f"   Secrets removed: {cleanup_result.secrets_removed}/{len(secrets_before)}")
    print(f"   Large files removed: {cleanup_result.large_files_removed}/{len(large_files)}")
    print(f"   Commits rewritten: {cleanup_result.commits_rewritten}")
    
    # =========================================================================
    # PHASE 5: VERIFY CLEANUP
    # =========================================================================
    print_header("PHASE 5: Verifying Cleanup")
    
    print("🔍 Re-scanning cleaned repository...")
    secrets_after = cleaner.scan_git_history(
        MIRROR_PATH,
        include_all_branches=True,
        show_progress=True
    )
    
    large_files_after = cleaner.scan_large_files(MIRROR_PATH, max_size_mb=100.0, show_progress=True)
    
    print()
    print("📊 Verification Results:")
    print(f"   Secrets BEFORE: {len(secrets_before)}")
    print(f"   Secrets AFTER:  {len(secrets_after)}")
    print(f"   Large files BEFORE: {len(large_files)}")
    print(f"   Large files AFTER:  {len(large_files_after)}")
    
    if len(secrets_after) == 0 and len(large_files_after) == 0:
        print()
        print("✅ SUCCESS: Repository is now clean!")
    else:
        print()
        print("⚠️  WARNING: Some items may still remain")
        if secrets_after:
            print("   Remaining secrets:")
            for s in secrets_after[:5]:
                print(f"      - {s.secret_type}: {s.value[:30]}...")
    
    # =========================================================================
    # PHASE 6: GENERATE FINAL REPORT
    # =========================================================================
    print_header("PHASE 6: Generating Final Report")
    
    report_path = os.path.join(OUTPUT_DIR, f"{REPO_NAME}_SECURITY_AUDIT_REPORT.md")
    
    end_time = datetime.now()
    duration = end_time - start_time
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"# 🔐 Security Audit Report: {REPO_NAME}\n\n")
        f.write(f"**Generated:** {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Duration:** {duration}\n\n")
        
        f.write("---\n\n")
        f.write("## 📊 Executive Summary\n\n")
        f.write("| Metric | Before | After | Status |\n")
        f.write("|--------|--------|-------|--------|\n")
        f.write(f"| Total Secrets | {len(secrets_before)} | {len(secrets_after)} | {'✅ Clean' if len(secrets_after) == 0 else '⚠️ Review'} |\n")
        f.write(f"| Critical Secrets | {severity_counts.get('critical', 0)} | {Counter(s.severity for s in secrets_after).get('critical', 0)} | {'✅ Clean' if Counter(s.severity for s in secrets_after).get('critical', 0) == 0 else '🔴 Action Required'} |\n")
        f.write(f"| High Secrets | {severity_counts.get('high', 0)} | {Counter(s.severity for s in secrets_after).get('high', 0)} | {'✅ Clean' if Counter(s.severity for s in secrets_after).get('high', 0) == 0 else '🟠 Action Required'} |\n")
        f.write(f"| Large Files (>100MB) | {len(large_files)} | {len(large_files_after)} | {'✅ Clean' if len(large_files_after) == 0 else '⚠️ Review'} |\n")
        
        f.write("\n---\n\n")
        f.write("## 🔴 Critical Secrets Found (BEFORE)\n\n")
        critical_secrets = [s for s in secrets_before if s.severity == "critical"]
        if critical_secrets:
            f.write("| Type | Suggested Env Var | Files | Commits |\n")
            f.write("|------|-------------------|-------|----------|\n")
            for s in critical_secrets[:50]:
                files_str = ", ".join(s.files[:2])
                f.write(f"| {s.secret_type} | `{s.suggested_env_var}` | {files_str} | {len(s.commits)} |\n")
        else:
            f.write("*No critical secrets found.*\n")
        
        f.write("\n---\n\n")
        f.write("## 🟠 High Severity Secrets Found (BEFORE)\n\n")
        high_secrets = [s for s in secrets_before if s.severity == "high"]
        if high_secrets:
            f.write("| Type | Suggested Env Var | Files | Commits |\n")
            f.write("|------|-------------------|-------|----------|\n")
            for s in high_secrets[:30]:
                files_str = ", ".join(s.files[:2])
                f.write(f"| {s.secret_type} | `{s.suggested_env_var}` | {files_str} | {len(s.commits)} |\n")
        else:
            f.write("*No high severity secrets found.*\n")
        
        f.write("\n---\n\n")
        f.write("## 📁 Large Files Found (BEFORE)\n\n")
        if large_files:
            f.write("| File | Size |\n")
            f.write("|------|------|\n")
            for file_path, size in large_files:
                f.write(f"| `{file_path}` | {format_size(size)} |\n")
        else:
            f.write("*No large files found.*\n")
        
        f.write("\n---\n\n")
        f.write("## ✅ Cleanup Actions Performed\n\n")
        f.write(f"1. **Mirror Clone Created:** `{MIRROR_PATH}`\n")
        f.write(f"2. **Secrets Removed:** {cleanup_result.secrets_removed} secrets purged from history\n")
        f.write(f"3. **Large Files Removed:** {cleanup_result.large_files_removed} files removed\n")
        f.write(f"4. **Git History Rewritten:** All branches cleaned\n")
        
        # =====================================================================
        # NEW SECTION: Uncleaned Secrets (secrets that remain after cleanup)
        # =====================================================================
        f.write("\n---\n\n")
        f.write("## ⚠️ Uncleaned Secrets (Require Manual Review)\n\n")
        
        if secrets_after:
            f.write(f"**{len(secrets_after)} secrets could not be automatically cleaned.**\n\n")
            f.write("These secrets remain because they contain special characters (newlines, null bytes) ")
            f.write("that cannot be processed by git-filter-repo, or they are false positives.\n\n")
            
            f.write("| # | Type | Env Var | Reason | Files | Action |\n")
            f.write("|---|------|---------|--------|-------|--------|\n")
            
            for idx, s in enumerate(secrets_after, 1):
                # Determine reason
                val = s.value
                reasons = []
                if len(val) < 4:
                    reasons.append("Too short")
                if '\n' in val or '\r' in val:
                    reasons.append("Contains newline")
                if '\x00' in val:
                    reasons.append("Contains null byte")
                if 'url_with_credentials' in s.secret_type.lower():
                    reasons.append("Likely false positive (URL)")
                
                reason_str = ", ".join(reasons) if reasons else "Unknown"
                
                # Determine action
                if 'url_with_credentials' in s.secret_type.lower() and ('atlassian' in val.lower() or 'github.io' in val.lower() or 'w3.org' in val.lower()):
                    action = "✅ Safe to ignore (not a secret)"
                elif reasons and 'newline' in str(reasons).lower():
                    action = "🔧 Manual removal required"
                else:
                    action = "⚠️ Review manually"
                
                files_str = ", ".join(s.files[:2]) if s.files else "Unknown"
                f.write(f"| {idx} | {s.secret_type} | `{s.suggested_env_var[:40]}` | {reason_str} | {files_str[:30]} | {action} |\n")
            
            f.write("\n### Manual Cleanup Instructions\n\n")
            f.write("For secrets marked as '🔧 Manual removal required':\n\n")
            f.write("1. **Edit the file directly** and remove/replace the secret value\n")
            f.write("2. **Commit the change:** `git commit -am 'Remove secret manually'`\n")
            f.write("3. **Force push:** `git push --force`\n\n")
            f.write("**Note:** For multi-line secrets (like private keys with newlines), ")
            f.write("you may need to use `git filter-repo --blob-callback` for complex replacements.\n")
        else:
            f.write("✅ **All secrets were successfully cleaned!** No manual action required.\n")
        
        f.write("\n---\n\n")
        f.write("## 🚀 Next Steps\n\n")
        f.write("### 1. Set Up GitHub Secrets\n")
        f.write("```bash\n")
        f.write("# Authenticate with GitHub\n")
        f.write("gh auth login\n\n")
        f.write("# Run the generated script\n")
        f.write(f"bash {gh_script_path}\n")
        f.write("```\n\n")
        
        f.write("### 2. Push Cleaned Repository\n")
        f.write("```bash\n")
        f.write(f"cd {MIRROR_PATH}\n")
        f.write("git remote add github https://github.com/OWNER/REPO.git\n")
        f.write("git push github --all --force\n")
        f.write("git push github --tags --force\n")
        f.write("```\n\n")
        
        f.write("### 3. Notify Team\n")
        f.write("All team members must re-clone the repository:\n")
        f.write("```bash\n")
        f.write("rm -rf old-repo\n")
        f.write("git clone https://github.com/OWNER/REPO.git\n")
        f.write("```\n\n")
        
        f.write("### 4. Rotate Credentials\n")
        f.write("**⚠️ IMPORTANT:** All exposed secrets should be rotated immediately:\n")
        for typ in list(type_counts.keys())[:10]:
            if "password" in typ.lower() or "key" in typ.lower() or "secret" in typ.lower() or "token" in typ.lower():
                f.write(f"- [ ] Rotate {typ}\n")
        
        f.write("\n---\n\n")
        f.write("## 📋 Files Generated\n\n")
        f.write(f"| File | Description |\n")
        f.write(f"|------|-------------|\n")
        f.write(f"| `{REPO_NAME}_secrets_BEFORE.json` | All secrets with metadata |\n")
        f.write(f"| `{REPO_NAME}_secrets_UNCLEANED.json` | Secrets that could not be cleaned |\n")
        f.write(f"| `{REPO_NAME}_secrets.env` | Secrets in .env format |\n")
        f.write(f"| `{REPO_NAME}_set_github_secrets.sh` | GitHub CLI setup script |\n")
        f.write(f"| `{REPO_NAME}_SECURITY_AUDIT_REPORT.md` | This report |\n")
    
    print(f"✅ Report saved: {report_path}")
    
    # Export uncleaned secrets to JSON
    uncleaned_path = os.path.join(OUTPUT_DIR, f"{REPO_NAME}_secrets_UNCLEANED.json")
    uncleaned_data = {
        "repository": REPO_NAME,
        "scan_date": datetime.now().isoformat(),
        "total_before": len(secrets_before),
        "total_after": len(secrets_after),
        "cleaned": len(secrets_before) - len(secrets_after),
        "uncleaned": len(secrets_after),
        "secrets": []
    }
    
    for s in secrets_after:
        val = s.value
        reasons = []
        if len(val) < 4:
            reasons.append("too_short")
        if '\n' in val or '\r' in val:
            reasons.append("contains_newline")
        if '\x00' in val:
            reasons.append("contains_null")
        if 'url_with_credentials' in s.secret_type.lower():
            reasons.append("likely_false_positive")
        
        uncleaned_data["secrets"].append({
            "env_var": s.suggested_env_var,
            "type": s.secret_type,
            "severity": s.severity,
            "files": s.files[:5],
            "commit_count": len(s.commits),
            "value_preview": s.value[:50] + "..." if len(s.value) > 50 else s.value,
            "skip_reasons": reasons,
            "is_false_positive": 'url_with_credentials' in s.secret_type.lower() and any(x in s.value.lower() for x in ['atlassian', 'github.io', 'w3.org', 'karma-runner'])
        })
    
    with open(uncleaned_path, "w", encoding="utf-8") as f:
        json.dump(uncleaned_data, f, indent=2, ensure_ascii=False)
    print(f"✅ Uncleaned secrets: {uncleaned_path}")
    
    # =========================================================================
    # FINAL SUMMARY
    # =========================================================================
    print_header("COMPLETE!")
    
    print(f"⏱️  Total time: {duration}")
    print()
    print("📁 Output files:")
    for f in os.listdir(OUTPUT_DIR):
        size = os.path.getsize(os.path.join(OUTPUT_DIR, f))
        print(f"   • {f} ({format_size(size)})")
    
    print()
    print("📊 Final Status:")
    print(f"   Secrets: {len(secrets_before)} → {len(secrets_after)}")
    print(f"   Large Files: {len(large_files)} → {len(large_files_after)}")
    
    if len(secrets_after) == 0 and len(large_files_after) == 0:
        print()
        print("🎉 Repository is now CLEAN and ready to push!")
        print()
        print("Next steps:")
        print(f"   1. Review the report: {report_path}")
        print(f"   2. Set up GitHub secrets: bash {gh_script_path}")
        print(f"   3. Push the cleaned repo from: {MIRROR_PATH}")
    else:
        print()
        print("⚠️  Some items may still need attention. Check the report.")

if __name__ == "__main__":
    main()
