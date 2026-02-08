#!/usr/bin/env python3
"""
Generate GitHub Actions Workflow from DeployGuard scan results.

This script reads a DeployGuard scan report (JSON) and generates a 
GitHub Actions workflow file with all secrets properly mapped for .NET.

Usage:
    python generate_github_workflow.py --scan-report scan_results.json --output .github/workflows/deploy.yml
"""

import json
import argparse
import re
from pathlib import Path
from typing import Dict, List, Any


def load_scan_report(report_path: str) -> Dict[str, Any]:
    """Load scan report from JSON file."""
    with open(report_path, 'r') as f:
        return json.load(f)


def extract_secrets_from_report(report: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Extract secrets from scan report and generate env var names.
    
    Returns list of dicts with:
        - env_var: The .NET environment variable name (without DG_ prefix)
        - github_secret: The GitHub secret name (with DG_ prefix)
        - file_path: Original file path where secret was found
        - secret_type: Type of secret detected
    """
    secrets = []
    seen_env_vars = set()
    
    for file_path, findings in report.get('files', {}).items():
        for finding in findings:
            secret_type = finding.get('type', finding.get('rule_id', 'unknown'))
            
            # Extract JSON context if available
            json_section = finding.get('json_section', '')
            json_key = finding.get('json_key', '')
            
            # If we have JSON context, use it
            if json_section and json_key:
                env_var = f"{json_section}__{json_key}"
            elif json_key:
                env_var = json_key
            else:
                # Fallback: generate from secret type and file
                file_stem = Path(file_path).stem.replace('.', '_').replace('-', '_')
                type_name = re.sub(r'[^a-zA-Z0-9]', '_', secret_type)
                env_var = f"{file_stem}__{type_name}"
            
            # Clean up env var name
            env_var = re.sub(r'[^a-zA-Z0-9_]', '_', env_var)
            env_var = re.sub(r'_+', '_', env_var)  # Remove multiple underscores
            env_var = env_var.strip('_')
            
            # Add DG_ prefix for GitHub secret name
            github_secret = f"DG_{env_var}"
            
            if env_var not in seen_env_vars:
                seen_env_vars.add(env_var)
                secrets.append({
                    'env_var': env_var,
                    'github_secret': github_secret,
                    'file_path': file_path,
                    'secret_type': secret_type
                })
    
    return secrets


def categorize_secrets(secrets: List[Dict[str, str]]) -> Dict[str, List[Dict[str, str]]]:
    """Categorize secrets by type for better organization."""
    categories = {
        'connection_strings': [],
        'api_keys': [],
        'authentication': [],
        'encryption_keys': [],
        'other': []
    }
    
    for secret in secrets:
        env_var = secret['env_var'].lower()
        secret_type = secret['secret_type'].lower()
        
        if 'connection' in env_var or 'connectionstring' in secret_type:
            categories['connection_strings'].append(secret)
        elif 'api' in env_var or 'apikey' in secret_type:
            categories['api_keys'].append(secret)
        elif any(x in env_var for x in ['auth', 'oauth', 'client_secret', 'password', 'token']):
            categories['authentication'].append(secret)
        elif any(x in env_var for x in ['key', 'private', 'secret', 'encrypt']):
            categories['encryption_keys'].append(secret)
        else:
            categories['other'].append(secret)
    
    return categories


def generate_workflow(secrets: List[Dict[str, str]], dotnet_version: str = '8.0.x') -> str:
    """Generate GitHub Actions workflow YAML content."""
    
    categories = categorize_secrets(secrets)
    
    # Build env section
    env_lines = []
    
    if categories['connection_strings']:
        env_lines.append("        # === CONNECTION STRINGS ===")
        for s in categories['connection_strings']:
            env_lines.append(f"        {s['env_var']}: ${{{{ secrets.{s['github_secret']} }}}}")
        env_lines.append("")
    
    if categories['authentication']:
        env_lines.append("        # === AUTHENTICATION / OAUTH ===")
        for s in categories['authentication']:
            env_lines.append(f"        {s['env_var']}: ${{{{ secrets.{s['github_secret']} }}}}")
        env_lines.append("")
    
    if categories['api_keys']:
        env_lines.append("        # === API KEYS ===")
        for s in categories['api_keys']:
            env_lines.append(f"        {s['env_var']}: ${{{{ secrets.{s['github_secret']} }}}}")
        env_lines.append("")
    
    if categories['encryption_keys']:
        env_lines.append("        # === ENCRYPTION / SECURITY KEYS ===")
        for s in categories['encryption_keys']:
            env_lines.append(f"        {s['env_var']}: ${{{{ secrets.{s['github_secret']} }}}}")
        env_lines.append("")
    
    if categories['other']:
        env_lines.append("        # === OTHER SECRETS ===")
        for s in categories['other']:
            env_lines.append(f"        {s['env_var']}: ${{{{ secrets.{s['github_secret']} }}}}")
        env_lines.append("")
    
    env_block = "\n".join(env_lines)
    
    workflow = f'''name: Build and Deploy

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]
  workflow_dispatch:

env:
  DOTNET_VERSION: '{dotnet_version}'

jobs:
  build:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Setup .NET
      uses: actions/setup-dotnet@v4
      with:
        dotnet-version: ${{{{ env.DOTNET_VERSION }}}}
    
    - name: Restore dependencies
      run: dotnet restore
    
    - name: Build
      env:
        # =============================================================
        # .NET ENVIRONMENT VARIABLE OVERRIDES
        # =============================================================
        # These environment variables override appsettings.json values.
        # .NET uses __ (double underscore) as hierarchy separator.
        #
        # Example:
        #   appsettings.json: {{"ConnectionStrings": {{"HubDb": "..."}}}}
        #   Env Var:          ConnectionStrings__HubDb
        # =============================================================
        
{env_block}
      run: dotnet build --configuration Release --no-restore
    
    - name: Test
      env:
{env_block}
      run: dotnet test --no-build --verbosity normal --configuration Release
    
    - name: Publish
      run: dotnet publish --configuration Release --no-build --output ./publish
    
    - name: Upload artifact
      uses: actions/upload-artifact@v4
      with:
        name: app-package
        path: ./publish

  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment: production
    
    steps:
    - name: Download artifact
      uses: actions/download-artifact@v4
      with:
        name: app-package
        path: ./publish
    
    - name: Deploy
      env:
{env_block}
      run: |
        echo "Deploying application..."
        # Add your deployment commands here
        # Examples:
        # - Azure: az webapp deploy --name myapp --src ./publish
        # - Docker: docker build -t myapp . && docker push myapp
        # - SSH: scp -r ./publish user@server:/var/www/app
'''
    
    return workflow


def generate_secrets_list(secrets: List[Dict[str, str]]) -> str:
    """Generate a markdown list of secrets to create in GitHub."""
    
    lines = [
        "# GitHub Secrets to Create",
        "",
        "Create the following secrets in your GitHub repository settings:",
        "(Settings > Secrets and variables > Actions > New repository secret)",
        "",
        "| Secret Name | Description | Source File |",
        "|-------------|-------------|-------------|"
    ]
    
    for s in secrets:
        lines.append(f"| `{s['github_secret']}` | {s['secret_type']} | {s['file_path']} |")
    
    lines.extend([
        "",
        "## How .NET Uses These",
        "",
        "In your `appsettings.json`, values will be empty strings:",
        "```json",
        "{",
        '  "ConnectionStrings": {',
        '    "HubDbContext": ""',
        "  }",
        "}",
        "```",
        "",
        "GitHub Actions sets environment variables like `ConnectionStrings__HubDbContext`.",
        ".NET automatically overrides the empty config value with the environment variable.",
    ])
    
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Generate GitHub Actions workflow from DeployGuard scan results'
    )
    parser.add_argument(
        '--scan-report', '-s',
        required=True,
        help='Path to DeployGuard scan report (JSON)'
    )
    parser.add_argument(
        '--output', '-o',
        default='.github/workflows/deploy.yml',
        help='Output path for workflow file'
    )
    parser.add_argument(
        '--secrets-list', '-l',
        help='Optional: Output path for secrets list markdown'
    )
    parser.add_argument(
        '--dotnet-version',
        default='8.0.x',
        help='.NET version to use (default: 8.0.x)'
    )
    parser.add_argument(
        '--env-mapping',
        help='Optional: Path to JSON with env_var mapping from history cleaner'
    )
    
    args = parser.parse_args()
    
    # Load scan report
    report = load_scan_report(args.scan_report)
    
    # If we have an env_mapping file, use it directly
    if args.env_mapping:
        with open(args.env_mapping, 'r') as f:
            mapping = json.load(f)
        
        secrets = []
        for env_var, info in mapping.items():
            secrets.append({
                'env_var': env_var.replace('DG_', ''),  # Remove prefix for .NET env var
                'github_secret': env_var,  # Keep prefix for GitHub
                'file_path': info.get('file_path', 'unknown'),
                'secret_type': info.get('secret_type', 'unknown')
            })
    else:
        # Extract secrets from scan report
        secrets = extract_secrets_from_report(report)
    
    if not secrets:
        print("No secrets found in scan report!")
        return 1
    
    print(f"Found {len(secrets)} secrets to map")
    
    # Generate workflow
    workflow_content = generate_workflow(secrets, args.dotnet_version)
    
    # Create output directory
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write workflow
    with open(output_path, 'w') as f:
        f.write(workflow_content)
    
    print(f"Generated workflow: {output_path}")
    
    # Generate secrets list if requested
    if args.secrets_list:
        secrets_content = generate_secrets_list(secrets)
        with open(args.secrets_list, 'w') as f:
            f.write(secrets_content)
        print(f"Generated secrets list: {args.secrets_list}")
    
    # Also print secrets for reference
    print("\n=== Secrets to Create in GitHub ===")
    for s in secrets:
        print(f"  {s['github_secret']}")
    
    return 0


if __name__ == "__main__":
    exit(main())
