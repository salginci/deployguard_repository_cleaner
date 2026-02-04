#!/usr/bin/env python3
"""Detailed security scan for order-processing"""
from deployguard.core.scanner import SecretScanner
from datetime import datetime
import json

repo_path = '/Users/salginci/Source/FABA/order-processing'

print('🔍 DeployGuard - Detailed Security Scan')
print('=' * 70)
print(f'Repository: {repo_path}\n')

scanner = SecretScanner()
start = datetime.now()
findings_dict = scanner.scan_directory(repo_path)
end = datetime.now()

# Flatten findings
all_findings = []
for file_path, file_findings in findings_dict.items():
    all_findings.extend(file_findings)

print(f'✅ Scan Complete!')
print(f'Files Scanned: {len(findings_dict)}')
print(f'Total Findings: {len(all_findings)}')
print(f'Duration: {(end-start).total_seconds():.2f}s\n')

# Group by severity
by_severity = {}
for f in all_findings:
    sev = f.severity.value.upper()
    by_severity.setdefault(sev, []).append(f)

# Display summary
print('📊 SUMMARY BY SEVERITY:')
print('-' * 70)
for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
    count = len(by_severity.get(severity, []))
    if count > 0:
        print(f'  {severity:10} : {count:4} findings')

# Group by type
by_type = {}
for f in all_findings:
    secret_type = f.type.value if hasattr(f.type, 'value') else str(f.type)
    by_type.setdefault(secret_type, []).append(f)

print('\n📋 SUMMARY BY SECRET TYPE:')
print('-' * 70)
for secret_type, findings in sorted(by_type.items(), key=lambda x: len(x[1]), reverse=True)[:15]:
    print(f'  {secret_type:30} : {len(findings):4} findings')

# Show critical/high findings
critical = by_severity.get('CRITICAL', [])
high = by_severity.get('HIGH', [])
critical_high = critical + high

if critical_high:
    print(f'\n⚠️  CRITICAL & HIGH SEVERITY FINDINGS ({len(critical_high)} total):')
    print('=' * 70)
    for finding in critical_high[:20]:
        secret_type = finding.type.value if hasattr(finding.type, 'value') else str(finding.type)
        print(f'\n  🔴 {secret_type} ({finding.severity.value})')
        print(f'     File: {finding.file_path}:{finding.line_number}')
        print(f'     Value: {finding.mask_value()}')
        if finding.suggested_variable:
            print(f'     💡 Suggested: {finding.suggested_variable}')

# Show medium findings sample
medium = by_severity.get('MEDIUM', [])
if medium:
    print(f'\n⚠️  MEDIUM SEVERITY FINDINGS ({len(medium)} total) - Sample:')
    print('=' * 70)
    for finding in medium[:10]:
        secret_type = finding.type.value if hasattr(finding.type, 'value') else str(finding.type)
        print(f'  🟡 {secret_type}: {finding.file_path}:{finding.line_number}')

# Files with most findings
file_counts = {}
for file_path, file_findings in findings_dict.items():
    file_counts[file_path] = len(file_findings)

print(f'\n📂 FILES WITH MOST FINDINGS:')
print('-' * 70)
for file_path, count in sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
    print(f'  {count:4} findings: {file_path}')

# Save detailed report
report_file = 'order-processing-security-report.json'
report_data = {
    'repository': repo_path,
    'scan_date': start.isoformat(),
    'files_scanned': len(findings_dict),
    'total_findings': len(all_findings),
    'duration_seconds': (end-start).total_seconds(),
    'summary': {
        'by_severity': {k: len(v) for k, v in by_severity.items()},
        'by_type': {k: len(v) for k, v in by_type.items()}
    },
    'findings': [
        {
            'secret_type': f.type.value if hasattr(f.type, 'value') else str(f.type),
            'severity': f.severity.value,
            'file_path': f.file_path,
            'line_number': f.line_number,
            'masked_value': f.mask_value(),
            'suggested_variable': f.suggested_variable
        }
        for f in all_findings
    ]
}

with open(report_file, 'w') as file:
    json.dump(report_data, file, indent=2)

print(f'\n💾 Detailed report saved to: {report_file}')
print('\n📋 RECOMMENDATIONS:')
print('  1. Focus on CRITICAL and HIGH severity findings first')
print('  2. Use environment variables for all credentials')
print('  3. Add .env files to .gitignore')
print('  4. Rotate any exposed credentials immediately')
print('  5. Consider using AWS Secrets Manager or HashiCorp Vault')
