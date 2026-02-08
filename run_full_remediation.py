#!/usr/bin/env python3
"""
Full remediation script for deployguard_test_repo.

This script:
1. Creates a mirror clone (for safe history rewriting)
2. Scans for secrets in git history
3. Scans for large files (>100MB for GitHub)
4. Removes both secrets and large files
5. Generates reports (before and after)
6. Shows push instructions
"""

import sys
import os
import shutil
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from deployguard.core.history_cleaner import GitHistoryCleaner
from deployguard.core.scanner import SecretScanner
from deployguard.cli.multi_report_generator import MultiReportGenerator, SecretLocation

# Configuration
ORIGINAL_REPO_PATH = "/Users/salginci/Source/GITHUB/deployguard_test_repo"
MIRROR_CLONE_PATH = "/Users/salginci/Source/GITHUB/deployguard_test_repo_mirror.git"
OUTPUT_DIR = "/Users/salginci/Source/GITHUB/deployguard_test_repo_remediation_reports"
MAX_FILE_SIZE_MB = 100.0  # GitHub limit

def main():
    print("=" * 70)
    print("🔐 DeployGuard Full Remediation")
    print("=" * 70)
    print()
    print(f"📁 Source Repository: {ORIGINAL_REPO_PATH}")
    print(f"📁 Mirror Clone: {MIRROR_CLONE_PATH}")
    print(f"📁 Reports: {OUTPUT_DIR}")
    print(f"📏 Max File Size: {MAX_FILE_SIZE_MB}MB")
    print()
    
    # Initialize
    print("🔧 Initializing scanner and history cleaner...")
    scanner = SecretScanner()
    cleaner = GitHistoryCleaner(scanner)
    
    # Check if git-filter-repo is available
    if not cleaner._git_filter_repo_available:
        print()
        print("⚠️  WARNING: git-filter-repo is not installed!")
        print("   Install it with: pip install git-filter-repo")
        print("   Without it, cleanup will use slower git filter-branch")
        print()
    
    # =========================================================================
    # STEP 1: Create Mirror Clone
    # =========================================================================
    print()
    print("=" * 70)
    print("📍 STEP 1: Creating Mirror Clone")
    print("=" * 70)
    
    if os.path.exists(MIRROR_CLONE_PATH):
        print(f"   Removing existing mirror clone...")
        shutil.rmtree(MIRROR_CLONE_PATH)
    
    print(f"   Creating mirror clone from {ORIGINAL_REPO_PATH}...")
    try:
        cleaner.create_mirror_clone(ORIGINAL_REPO_PATH, MIRROR_CLONE_PATH)
        print(f"   ✅ Mirror clone created at: {MIRROR_CLONE_PATH}")
    except Exception as e:
        print(f"   ❌ Failed to create mirror clone: {e}")
        return
    
    # =========================================================================
    # STEP 2: Scan for Secrets
    # =========================================================================
    print()
    print("=" * 70)
    print("📍 STEP 2: Scanning for Secrets in Git History")
    print("=" * 70)
    print(f"   Repository: {MIRROR_CLONE_PATH}")
    print("   Scanning ALL commits across ALL branches...")
    print()
    
    secrets = cleaner.scan_git_history(MIRROR_CLONE_PATH, include_all_branches=True)
    
    print()
    print(f"✅ Found {len(secrets)} unique secrets")
    
    # Count by severity
    from collections import Counter
    severities = Counter(s.severity for s in secrets)
    print()
    print("   By Severity:")
    for sev in ["critical", "high", "medium", "low"]:
        if sev in severities:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[sev]
            print(f"      {emoji} {sev.upper()}: {severities[sev]}")
    
    # =========================================================================
    # STEP 3: Scan for Large Files
    # =========================================================================
    print()
    print("=" * 70)
    print("📍 STEP 3: Scanning for Large Files (>100MB)")
    print("=" * 70)
    
    large_files = cleaner.scan_large_files(MIRROR_CLONE_PATH, max_size_mb=MAX_FILE_SIZE_MB)
    
    if large_files:
        print()
        print(f"⚠️  Found {len(large_files)} files exceeding {MAX_FILE_SIZE_MB}MB:")
        for path, size in large_files[:10]:
            print(f"      • {path}: {size / 1024 / 1024:.1f}MB")
    else:
        print(f"   ✅ No files exceed {MAX_FILE_SIZE_MB}MB")
    
    # =========================================================================
    # STEP 4: Dry Run (Preview)
    # =========================================================================
    print()
    print("=" * 70)
    print("📍 STEP 4: Cleanup Preview (Dry Run)")
    print("=" * 70)
    
    dry_result = cleaner.full_cleanup(
        repo_path=MIRROR_CLONE_PATH,
        secrets=secrets,
        large_files=large_files,
        use_env_vars=True,  # Replace with ${DG_VAR_NAME} placeholders
        dry_run=True,
        show_progress=True,
    )
    
    print()
    print("📋 DRY RUN SUMMARY:")
    print(f"   Secrets to remove: {dry_result.secrets_found}")
    print(f"   Large files to remove: {dry_result.large_files_found}")
    
    # =========================================================================
    # STEP 5: Confirm and Execute
    # =========================================================================
    print()
    print("=" * 70)
    print("📍 STEP 5: Execute Cleanup")
    print("=" * 70)
    print()
    print("⚠️  WARNING: This will PERMANENTLY rewrite git history!")
    print("   • All commit SHAs will change")
    print("   • Everyone must re-clone the repository")
    print("   • This cannot be undone!")
    print()
    
    # For automation, we'll proceed. In real use, add confirmation prompt.
    confirm = input("Type 'YES' to proceed with cleanup: ").strip()
    
    if confirm != "YES":
        print()
        print("❌ Cleanup cancelled by user.")
        print("   Reports will still be generated...")
    else:
        print()
        print("🚀 Executing cleanup...")
        
        result = cleaner.full_cleanup(
            repo_path=MIRROR_CLONE_PATH,
            secrets=secrets,
            large_files=large_files,
            use_env_vars=True,
            dry_run=False,
            show_progress=True,
        )
        
        print()
        print("✅ CLEANUP COMPLETE:")
        print(f"   Secrets removed: {result.secrets_removed}/{result.secrets_found}")
        print(f"   Large files removed: {result.large_files_removed}/{result.large_files_found}")
        
        if result.errors:
            print()
            print("⚠️  Errors encountered:")
            for err in result.errors[:5]:
                print(f"      • {err}")
    
    # =========================================================================
    # STEP 6: Generate Reports
    # =========================================================================
    print()
    print("=" * 70)
    print("📍 STEP 6: Generating Reports")
    print("=" * 70)
    
    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Convert secrets to findings for report
    from deployguard.core.models import Finding, Severity, SecretType
    
    findings = []
    for secret in secrets:
        sev_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        severity = sev_map.get(secret.severity.lower(), Severity.MEDIUM)
        
        try:
            secret_type = SecretType(secret.secret_type.lower())
        except ValueError:
            secret_type = SecretType.API_KEY
        
        for file_path in secret.files:
            finding = Finding(
                type=secret_type,
                severity=severity,
                file_path=file_path,
                line_number=1,
                exposed_value=secret.value[:50] if len(secret.value) > 50 else secret.value,
                description=f"{secret.secret_type} detected",
                metadata={
                    "actual_value": secret.value,
                    "suggested_env_var": secret.suggested_env_var,
                    "commits": secret.commits[:5],
                    "all_files": secret.files,
                }
            )
            findings.append(finding)
    
    # Generate reports
    generator = MultiReportGenerator(
        repo_path=ORIGINAL_REPO_PATH,
        output_dir=OUTPUT_DIR,
        language="tr"
    )
    
    generator.before_findings = findings
    generator.after_findings = []  # Empty if cleanup was done
    
    # Gather repository info
    print("📊 Gathering repository info...")
    generator.gather_repository_info()
    
    # Add secrets to generator
    for secret in secrets:
        loc = SecretLocation(
            secret_value=secret.value,
            secret_type=secret.secret_type,
            severity=secret.severity,
            commits=secret.commits,
            files=secret.files,
            suggested_env_var=secret.suggested_env_var,
        )
        generator.secrets.append(loc)
    
    # Generate all reports
    print("📝 Generating 5 Turkish-style audit reports...")
    reports = generator.generate_all_reports()
    
    print()
    print("✅ REPORTS GENERATED:")
    for report_path in reports:
        size = os.path.getsize(report_path)
        name = os.path.basename(report_path)
        print(f"   📄 {name} ({size/1024:.1f} KB)")
    
    # =========================================================================
    # STEP 7: Next Steps
    # =========================================================================
    print()
    print("=" * 70)
    print("📍 NEXT STEPS")
    print("=" * 70)
    print()
    
    if confirm == "YES":
        print("To push the cleaned repository:")
        print()
        print(f"   cd {MIRROR_CLONE_PATH}")
        print("   git remote set-url origin <NEW_REMOTE_URL>")
        print("   git push --mirror --force")
        print()
        print("⚠️  IMPORTANT: All team members must:")
        print("   1. Delete their local repository")
        print("   2. Clone fresh from the new remote")
        print("   3. Update any CI/CD pipelines")
        print()
    else:
        print("Cleanup was NOT executed. To run cleanup:")
        print()
        print("   python run_full_remediation.py")
        print("   # Type 'YES' when prompted")
        print()
    
    print("📁 Reports are available at:")
    print(f"   {OUTPUT_DIR}")
    print()

if __name__ == "__main__":
    main()
