"""Quick test script to demonstrate DeployGuard scanning capabilities."""

from deployguard.core.scanner import SecretScanner
from deployguard.core.models import Severity

# Sample code with secrets (using obviously fake test values)
test_code = """
import os

# AWS Credentials - DANGER!
AWS_ACCESS_KEY = "AKIAFAKEKEY12345FAKE"
AWS_SECRET_KEY = "fakesecretkey1234567890fakefakefakefake"

# GitHub Token
GITHUB_TOKEN = "ghp_fake1234567890fake1234567890fake12"

# Database connection
DATABASE_URL = "mongodb://admin:testpassword@localhost:27017/mydb"

# API Key
API_KEY = "sk_test_fake1234567890fake1234567890fake"
"""

def main():
    print("🛡️  DeployGuard Secret Scanner - Quick Test\n")
    print("=" * 60)
    
    # Initialize scanner
    scanner = SecretScanner()
    print("✅ Scanner initialized with default patterns\n")
    
    # Scan the test code
    print("🔍 Scanning code for secrets...\n")
    findings = scanner.scan_file("test_sample.py", test_code)
    
    # Display results
    print(f"📊 Found {len(findings)} potential secrets:\n")
    
    for i, finding in enumerate(findings, 1):
        print(f"{i}. {finding.type.value.upper()}")
        print(f"   Severity: {finding.severity.value.upper()}")
        print(f"   Location: Line {finding.line_number}")
        print(f"   Exposed: {finding.mask_value()}")
        print(f"   Suggested Variable: {finding.suggested_variable or 'N/A'}")
        print(f"   Description: {finding.description}")
        print()
    
    # Test variable name generation
    print("🔤 Testing variable name generation:")
    from deployguard.core.models import SecretType
    
    existing_vars = set()
    for secret_type in [SecretType.AWS_ACCESS_KEY, SecretType.GITHUB_TOKEN, SecretType.API_KEY]:
        var_name = scanner.generate_variable_name(secret_type, existing_vars)
        existing_vars.add(var_name)
        print(f"   {secret_type.value} → {var_name}")
    
    # Test duplicate handling
    var_name_dup = scanner.generate_variable_name(SecretType.AWS_ACCESS_KEY, existing_vars)
    print(f"   {SecretType.AWS_ACCESS_KEY.value} (duplicate) → {var_name_dup}")
    
    print("\n" + "=" * 60)
    print("✅ Test completed successfully!")

if __name__ == "__main__":
    main()
