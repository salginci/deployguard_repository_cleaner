#!/usr/bin/env python3
"""
Quick scan script for your repositories
"""
import sys
from deployguard.core.scanner import SecretScanner
from pathlib import Path
from datetime import datetime

def scan_repository(repo_path):
    """Scan a repository and display results"""
    print(f'🔍 DeployGuard - Scanning Repository')
    print('=' * 70)
    print(f'Path: {repo_path}\n')
    
    scanner = SecretScanner()
    start = datetime.now()
    
    try:
        findings_dict = scanner.scan_directory(repo_path)
        end = datetime.now()
        
        # Flatten findings
        all_findings = []
        for file_path, file_findings in findings_dict.items():
            all_findings.extend(file_findings)
        
        # Display summary
        print(f'✅ Scan Complete!')
        print(f'Files Scanned: {len(findings_dict)}')
        print(f'Total Findings: {len(all_findings)}')
        print(f'Duration: {(end-start).total_seconds():.2f}s')
        
        if len(all_findings) == 0:
            print('\n✅ No secrets detected! Your repository is clean.')
            return
        
        # Group by severity
        by_severity = {}
        for finding in all_findings:
            severity = finding.severity.value
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)
        
        # Display findings
        print(f'\n⚠️  SECURITY FINDINGS:\n')
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in by_severity:
                findings = by_severity[severity]
                print(f'{severity} Severity: {len(findings)} findings')
                print('-' * 70)
                
                for finding in findings[:5]:  # Show first 5 of each severity
                    print(f'  Secret Type: {finding.secret_type}')
                    print(f'  File: {finding.file_path}')
                    print(f'  Line: {finding.line_number}')
                    print(f'  Masked Value: {finding.masked_value}')
                    if finding.suggested_variable:
                        print(f'  💡 Suggested Variable: {finding.suggested_variable}')
                    print()
                
                if len(findings) > 5:
                    print(f'  ... and {len(findings) - 5} more {severity} findings\n')
        
        # Recommendations
        print('\n📋 RECOMMENDATIONS:')
        print('1. Remove hardcoded secrets from your code')
        print('2. Use environment variables instead')
        print('3. Add sensitive files to .gitignore')
        print('4. Rotate exposed credentials immediately')
        print('5. Use secret management tools (AWS Secrets Manager, HashiCorp Vault)')
        
    except Exception as e:
        print(f'❌ Error scanning repository: {e}')
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    if len(sys.argv) > 1:
        repo_path = sys.argv[1]
    else:
        # Default: scan Bilyoner_Parser
        repo_path = '/Users/salginci/Source/UOL/Bilyoner_Parser'
    
    if not Path(repo_path).exists():
        print(f'❌ Path does not exist: {repo_path}')
        print(f'\nUsage: python {sys.argv[0]} /path/to/repository')
        sys.exit(1)
    
    scan_repository(repo_path)
