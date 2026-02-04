#!/usr/bin/env python3
"""
DeployGuard - Production Usage Example
This shows how to scan a GitHub repository for secrets
"""
import os
from pathlib import Path
from deployguard.core.scanner import SecretScanner
from deployguard.platforms.github_adapter import GitHubAdapter
from deployguard.core.models import ScanResult, Severity
import tempfile
import shutil


def scan_github_repo(repo_url: str, github_token: str):
    """
    Scan a GitHub repository for exposed secrets
    
    Args:
        repo_url: GitHub repository URL (e.g., 'owner/repo')
        github_token: GitHub Personal Access Token
    """
    print(f"🔐 DeployGuard - Scanning {repo_url}")
    print("=" * 60)
    
    # Initialize GitHub adapter
    github = GitHubAdapter(github_token)
    
    # Get repository details
    try:
        repo = github.get_repositories(repo_url.split('/')[0])[0]
        print(f"✅ Connected to: {repo.name}")
        print(f"   Owner: {repo.owner}")
        print(f"   URL: {repo.url}")
    except Exception as e:
        print(f"❌ Failed to connect: {e}")
        return
    
    # Clone repository to temp directory
    temp_dir = Path(tempfile.mkdtemp())
    print(f"\n📥 Cloning to: {temp_dir}")
    
    try:
        # Clone using git
        os.system(f"git clone {repo.url} {temp_dir}/repo")
        repo_path = temp_dir / "repo"
        
        # Initialize scanner
        scanner = SecretScanner()
        print(f"\n🔍 Scanning for secrets...")
        
        # Scan the repository
        scan_result = scanner.scan_directory(str(repo_path))
        
        # Display results
        print(f"\n📊 SCAN RESULTS")
        print("=" * 60)
        print(f"Repository: {repo.name}")
        print(f"Total Files Scanned: {scan_result.files_scanned}")
        print(f"Total Secrets Found: {scan_result.total_findings}")
        print(f"Scan Duration: {scan_result.duration_seconds:.2f}s")
        
        if scan_result.total_findings > 0:
            print(f"\n⚠️  CRITICAL FINDINGS:")
            
            # Group by severity
            by_severity = scan_result.findings_by_severity()
            
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
                findings = by_severity.get(severity, [])
                if findings:
                    print(f"\n{severity.value} Severity: {len(findings)} findings")
                    for finding in findings[:5]:  # Show first 5 of each
                        print(f"  • {finding.secret_type}")
                        print(f"    File: {finding.file_path}")
                        print(f"    Line: {finding.line_number}")
                        print(f"    Value: {finding.masked_value}")
                        if finding.suggested_variable:
                            print(f"    Suggested Var: {finding.suggested_variable}")
                        print()
                    
                    if len(findings) > 5:
                        print(f"  ... and {len(findings) - 5} more")
        else:
            print("\n✅ No secrets detected!")
        
        # Generate report
        report_path = Path("deployguard_report.txt")
        with open(report_path, 'w') as f:
            f.write(f"DeployGuard Security Scan Report\n")
            f.write(f"Repository: {repo.name}\n")
            f.write(f"Scan Date: {scan_result.started_at}\n")
            f.write(f"=" * 60 + "\n\n")
            
            for finding in scan_result.findings:
                f.write(f"Secret Type: {finding.secret_type}\n")
                f.write(f"Severity: {finding.severity.value}\n")
                f.write(f"File: {finding.file_path}\n")
                f.write(f"Line: {finding.line_number}\n")
                f.write(f"Masked Value: {finding.masked_value}\n")
                if finding.suggested_variable:
                    f.write(f"Suggested Variable: {finding.suggested_variable}\n")
                f.write(f"\n{'-' * 60}\n\n")
        
        print(f"\n📄 Report saved to: {report_path.absolute()}")
        
    finally:
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)
        print(f"\n🧹 Cleaned up temporary files")


def scan_local_directory(directory_path: str):
    """
    Scan a local directory for secrets
    
    Args:
        directory_path: Path to directory to scan
    """
    print(f"🔐 DeployGuard - Scanning Local Directory")
    print("=" * 60)
    print(f"Path: {directory_path}")
    
    scanner = SecretScanner()
    scan_result = scanner.scan_directory(directory_path)
    
    print(f"\n📊 SCAN RESULTS")
    print("=" * 60)
    print(f"Files Scanned: {scan_result.files_scanned}")
    print(f"Secrets Found: {scan_result.total_findings}")
    print(f"Duration: {scan_result.duration_seconds:.2f}s")
    
    if scan_result.total_findings > 0:
        print(f"\n⚠️  FINDINGS:")
        for finding in scan_result.findings:
            print(f"\n• {finding.secret_type} ({finding.severity.value})")
            print(f"  File: {finding.file_path}")
            print(f"  Line: {finding.line_number}")
            print(f"  Value: {finding.masked_value}")
    else:
        print("\n✅ No secrets detected!")


if __name__ == "__main__":
    import sys
    
    print("DeployGuard - Production Usage Example\n")
    print("Options:")
    print("1. Scan GitHub repository")
    print("2. Scan local directory")
    
    choice = input("\nSelect option (1 or 2): ").strip()
    
    if choice == "1":
        repo = input("Enter GitHub repo (owner/repo): ").strip()
        token = input("Enter GitHub token: ").strip() or os.getenv("GITHUB_TOKEN")
        
        if not token:
            print("❌ GitHub token required!")
            sys.exit(1)
        
        scan_github_repo(repo, token)
        
    elif choice == "2":
        path = input("Enter directory path: ").strip()
        if not Path(path).exists():
            print(f"❌ Directory not found: {path}")
            sys.exit(1)
        
        scan_local_directory(path)
    else:
        print("Invalid choice!")
