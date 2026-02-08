#!/usr/bin/env python3
"""
Full analysis and report generation for deployguard_test_repo.
This runs the complete DeployGuard workflow:
1. Scan full git history
2. Generate 5 Turkish-style audit reports
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from deployguard.core.history_cleaner import GitHistoryCleaner
from deployguard.core.scanner import SecretScanner
from deployguard.cli.multi_report_generator import MultiReportGenerator, SecretLocation
from collections import Counter

# Configuration
REPO_PATH = "/Users/salginci/Source/GITHUB/deployguard_test_repo"
OUTPUT_DIR = "/Users/salginci/Source/GITHUB/deployguard_test_repo_reports"

def main():
    print("=" * 60)
    print("🔐 DeployGuard Full Analysis & Report Generation")
    print("=" * 60)
    print()
    
    # Initialize
    print("🔧 Initializing scanner and history cleaner...")
    scanner = SecretScanner()
    cleaner = GitHistoryCleaner(scanner)
    
    # Step 1: Scan full git history
    print()
    print("=" * 60)
    print("📍 STEP 1: Scanning Full Git History")
    print("=" * 60)
    print(f"   Repository: {REPO_PATH}")
    print("   Scanning ALL commits across ALL branches...")
    print()
    
    secrets = cleaner.scan_git_history(REPO_PATH, include_all_branches=True)
    
    print(f"✅ Found {len(secrets)} unique secrets in git history")
    print()
    
    # Summary by type
    types = Counter(s.secret_type for s in secrets)
    print("📊 By Secret Type:")
    for t, c in types.most_common(15):
        print(f"   • {t}: {c}")
    print()
    
    # Summary by severity
    severities = Counter(s.severity for s in secrets)
    print("🎯 By Severity:")
    for s, c in sorted(severities.items(), key=lambda x: ["critical", "high", "medium", "low"].index(x[0]) if x[0] in ["critical", "high", "medium", "low"] else 99):
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(s, "⚪")
        print(f"   {emoji} {s.upper()}: {c}")
    print()
    
    # Convert SecretMatch to Finding-like objects for the report generator
    from deployguard.core.models import Finding, Severity, SecretType
    
    findings = []
    for secret in secrets:
        # Map severity string to enum
        sev_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        severity = sev_map.get(secret.severity.lower(), Severity.MEDIUM)
        
        # Map secret type string to enum - use the string directly as SecretType is flexible
        try:
            secret_type = SecretType(secret.secret_type.lower())
        except ValueError:
            # If not in enum, use API_KEY as fallback
            secret_type = SecretType.API_KEY
        
        # Create a finding for each file where the secret was found
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
    
    print(f"📋 Converted to {len(findings)} finding records")
    print()
    
    # Step 2: Generate Reports
    print("=" * 60)
    print("📍 STEP 2: Generating 5 Turkish-Style Audit Reports")
    print("=" * 60)
    
    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Initialize report generator
    generator = MultiReportGenerator(
        repo_path=REPO_PATH,
        output_dir=OUTPUT_DIR,
        language="tr"
    )
    
    # Set the findings data
    generator.before_findings = findings
    generator.after_findings = []  # No cleanup done yet
    
    # Gather repository info
    print()
    print("📊 Gathering repository info...")
    generator.gather_repository_info()
    print(f"   Repository: {generator.metrics.name}")
    print(f"   Commits: {generator.metrics.total_commits}")
    print(f"   Branches: {generator.metrics.total_branches}")
    
    # Convert secrets to SecretLocation objects
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
    print()
    reports = generator.generate_all_reports()
    
    print()
    print("=" * 60)
    print("✅ REPORT GENERATION COMPLETE")
    print("=" * 60)
    print()
    print(f"📁 Output Directory: {OUTPUT_DIR}")
    print()
    print("📄 Generated Reports:")
    for report_path in reports:
        size = os.path.getsize(report_path)
        name = os.path.basename(report_path)
        print(f"   • {name} ({size/1024:.1f} KB)")
    
    print()
    print("🔍 Key Findings Summary:")
    print(f"   • Total unique secrets: {len(secrets)}")
    print(f"   • CRITICAL: {severities.get('critical', 0)}")
    print(f"   • HIGH: {severities.get('high', 0)}")
    print(f"   • Files affected: {len(set(s.files[0] for s in secrets if s.files))}")
    print()
    
    # Show sample secrets
    print("📌 Sample Secrets Found:")
    for i, secret in enumerate(secrets[:5], 1):
        masked = secret.value[:8] + "****" if len(secret.value) > 8 else "****"
        print(f"   {i}. [{secret.severity.upper()}] {secret.secret_type}")
        print(f"      Value: {masked}")
        print(f"      Files: {', '.join(secret.files[:2])}")
        print(f"      Commits: {len(secret.commits)}")
        print()
    
    if len(secrets) > 5:
        print(f"   ... and {len(secrets) - 5} more secrets")
    
    print()
    print("=" * 60)
    print("📖 Next Steps:")
    print("=" * 60)
    print("1. Review reports in:", OUTPUT_DIR)
    print("2. To clean the repository:")
    print(f"   deployguard clean history --path {REPO_PATH} --execute")
    print("3. To verify cleanup:")
    print(f"   deployguard scan history --path {REPO_PATH}")
    print()

if __name__ == "__main__":
    main()
