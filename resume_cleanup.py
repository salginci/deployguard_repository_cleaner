#!/usr/bin/env python3
"""
Resume cleanup from Phase 4 - uses existing scan results
"""

import os
import json
from datetime import datetime
from collections import Counter

# Setup paths
REPO_PATH = "/Users/salginci/Source/GITHUB/deployguard_test_repo"
MIRROR_PATH = "/Users/salginci/Source/GITHUB/deployguard_test_repo_mirror.git"
OUTPUT_DIR = "/Users/salginci/Source/GITHUB/deployguard_test_repo_security_audit"
REPO_NAME = "deployguard_test_repo"

# Import DeployGuard
from deployguard.core.scanner import SecretScanner
from deployguard.core.history_cleaner import GitHistoryCleaner


def format_size(size_bytes):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def print_header(title):
    print()
    print("=" * 80)
    print(f"🔐 {title}")
    print("=" * 80)


def main():
    start_time = datetime.now()
    
    # Check if mirror exists
    if not os.path.exists(MIRROR_PATH):
        print("❌ Mirror not found! Run full_workflow.py first.")
        return
    
    # Check for existing scan results
    secrets_json = os.path.join(OUTPUT_DIR, f"{REPO_NAME}_secrets_BEFORE.json")
    if not os.path.exists(secrets_json):
        print("❌ Scan results not found! Run full_workflow.py first.")
        return
    
    # Load existing scan results
    print_header("Loading Previous Scan Results")
    
    with open(secrets_json, "r") as f:
        data = json.load(f)
    
    secrets_before_raw = data.get("secrets", [])
    large_files = []
    
    # Check for large files JSON
    large_files_json = os.path.join(OUTPUT_DIR, f"{REPO_NAME}_large_files.json")
    if os.path.exists(large_files_json):
        with open(large_files_json, "r") as f:
            large_files = json.load(f)
    
    print(f"✅ Loaded {len(secrets_before_raw)} secrets from previous scan")
    print(f"✅ Loaded {len(large_files)} large files from previous scan")
    
    # Convert back to SecretMatch objects
    from deployguard.core.history_cleaner import SecretMatch
    import hashlib
    
    secrets_before = []
    for s in secrets_before_raw:
        value = s.get("value", "")
        value_hash = hashlib.sha256(value.encode()).hexdigest()[:16]
        secrets_before.append(SecretMatch(
            value=value,
            value_hash=value_hash,
            secret_type=s.get("secret_type", "unknown"),
            severity=s.get("severity", "medium"),
            suggested_env_var=s.get("suggested_env_var", ""),
            files=s.get("files", []),
            commits=s.get("commits", []),
        ))
    
    # Calculate severity counts
    severity_counts = Counter(s.severity for s in secrets_before)
    type_counts = Counter(s.secret_type for s in secrets_before)
    
    print()
    print(f"📊 Statistics:")
    print(f"   Critical: {severity_counts.get('critical', 0)}")
    print(f"   High: {severity_counts.get('high', 0)}")
    print(f"   Medium: {severity_counts.get('medium', 0)}")
    print(f"   Low: {severity_counts.get('low', 0)}")
    
    # =========================================================================
    # PHASE 4: RUN CLEANUP
    # =========================================================================
    print_header("PHASE 4: Running Cleanup on Mirror")
    
    cleaner = GitHistoryCleaner()
    
    print(f"   Found {len(secrets_before)} secrets to remove")
    print(f"   Found {len(large_files)} large files to remove")
    print()
    print("🧹 Running cleanup (this may take several minutes)...")
    print()
    
    cleanup_result = cleaner.full_cleanup(
        MIRROR_PATH,
        secrets=secrets_before,
        large_files=large_files,
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
    gh_script_path = os.path.join(OUTPUT_DIR, f"{REPO_NAME}_set_github_secrets.sh")
    
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
                files_str = ", ".join(s.files[:2]) if s.files else "N/A"
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
                files_str = ", ".join(s.files[:2]) if s.files else "N/A"
                f.write(f"| {s.secret_type} | `{s.suggested_env_var}` | {files_str} | {len(s.commits)} |\n")
        else:
            f.write("*No high severity secrets found.*\n")
        
        f.write("\n---\n\n")
        f.write("## 📁 Large Files Found (BEFORE)\n\n")
        if large_files:
            f.write("| File | Size |\n")
            f.write("|------|------|\n")
            for item in large_files:
                if isinstance(item, (list, tuple)):
                    file_path, size = item
                else:
                    file_path = item.get("path", "unknown")
                    size = item.get("size", 0)
                f.write(f"| `{file_path}` | {format_size(size)} |\n")
        else:
            f.write("*No large files found.*\n")
        
        f.write("\n---\n\n")
        f.write("## ✅ Cleanup Actions Performed\n\n")
        f.write(f"1. **Mirror Clone Created:** `{MIRROR_PATH}`\n")
        f.write(f"2. **Secrets Removed:** {cleanup_result.secrets_removed} secrets purged from history\n")
        f.write(f"3. **Large Files Removed:** {cleanup_result.large_files_removed} files removed\n")
        f.write(f"4. **Git History Rewritten:** All branches cleaned\n")
        
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
            if any(x in typ.lower() for x in ["password", "key", "secret", "token", "api"]):
                f.write(f"- [ ] Rotate {typ}\n")
        
        f.write("\n---\n\n")
        f.write("## 📋 Files Generated\n\n")
        f.write(f"| File | Description |\n")
        f.write(f"|------|-------------|\n")
        f.write(f"| `{REPO_NAME}_secrets_BEFORE.json` | All secrets with metadata |\n")
        f.write(f"| `{REPO_NAME}_secrets.env` | Secrets in .env format |\n")
        f.write(f"| `{REPO_NAME}_set_github_secrets.sh` | GitHub CLI setup script |\n")
        f.write(f"| `{REPO_NAME}_SECURITY_AUDIT_REPORT.md` | This report |\n")
    
    print(f"✅ Report saved: {report_path}")
    
    # =========================================================================
    # FINAL SUMMARY
    # =========================================================================
    print_header("COMPLETE!")
    
    print(f"⏱️  Total time: {duration}")
    print()
    print("📁 Output files:")
    for fname in os.listdir(OUTPUT_DIR):
        size = os.path.getsize(os.path.join(OUTPUT_DIR, fname))
        print(f"   • {fname} ({format_size(size)})")
    
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
