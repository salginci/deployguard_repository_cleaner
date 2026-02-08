#!/usr/bin/env python3
"""
Push cleaned secrets to GitHub Repository Secrets.

This script reads the secrets from the BEFORE scan and creates
GitHub repository secrets or environment secrets for each one.

Requirements:
    pip install PyNaCl requests

Usage:
    # Set your GitHub PAT
    export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"
    
    # Run the script
    python push_secrets_to_github.py --repo owner/repo --secrets-file path/to/secrets.json
    
    # Or with environment (recommended for prod secrets)
    python push_secrets_to_github.py --repo owner/repo --secrets-file path/to/secrets.json --environment production
"""

import argparse
import base64
import json
import os
import sys
from typing import Optional

try:
    from nacl import encoding, public
    import requests
except ImportError:
    print("❌ Missing dependencies. Install with:")
    print("   pip install PyNaCl requests")
    sys.exit(1)


class GitHubSecretsManager:
    """Manage GitHub repository and environment secrets."""
    
    def __init__(self, token: str, owner: str, repo: str):
        self.token = token
        self.owner = owner
        self.repo = repo
        self.base_url = f"https://api.github.com/repos/{owner}/{repo}"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
    
    def _encrypt_secret(self, public_key: str, secret_value: str) -> str:
        """Encrypt a secret using the repository's public key."""
        public_key_bytes = public.PublicKey(
            public_key.encode("utf-8"), 
            encoding.Base64Encoder()
        )
        sealed_box = public.SealedBox(public_key_bytes)
        encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
        return base64.b64encode(encrypted).decode("utf-8")
    
    def get_repo_public_key(self) -> tuple[str, str]:
        """Get the repository's public key for encrypting secrets."""
        url = f"{self.base_url}/actions/secrets/public-key"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        data = response.json()
        return data["key_id"], data["key"]
    
    def get_environment_public_key(self, environment: str) -> tuple[str, str]:
        """Get an environment's public key for encrypting secrets."""
        url = f"{self.base_url}/environments/{environment}/secrets/public-key"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        data = response.json()
        return data["key_id"], data["key"]
    
    def create_or_update_repo_secret(self, name: str, value: str) -> bool:
        """Create or update a repository secret."""
        try:
            key_id, public_key = self.get_repo_public_key()
            encrypted_value = self._encrypt_secret(public_key, value)
            
            url = f"{self.base_url}/actions/secrets/{name}"
            payload = {
                "encrypted_value": encrypted_value,
                "key_id": key_id
            }
            
            response = requests.put(url, headers=self.headers, json=payload)
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"   ❌ Error: {e}")
            return False
    
    def create_or_update_environment_secret(
        self, environment: str, name: str, value: str
    ) -> bool:
        """Create or update an environment secret."""
        try:
            # First ensure environment exists
            self._ensure_environment_exists(environment)
            
            key_id, public_key = self.get_environment_public_key(environment)
            encrypted_value = self._encrypt_secret(public_key, value)
            
            url = f"{self.base_url}/environments/{environment}/secrets/{name}"
            payload = {
                "encrypted_value": encrypted_value,
                "key_id": key_id
            }
            
            response = requests.put(url, headers=self.headers, json=payload)
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"   ❌ Error: {e}")
            return False
    
    def _ensure_environment_exists(self, environment: str) -> None:
        """Create environment if it doesn't exist."""
        url = f"{self.base_url}/environments/{environment}"
        # PUT will create if not exists
        requests.put(url, headers=self.headers, json={})
    
    def list_repo_secrets(self) -> list[str]:
        """List all repository secret names."""
        url = f"{self.base_url}/actions/secrets"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return [s["name"] for s in response.json().get("secrets", [])]
    
    def delete_repo_secret(self, name: str) -> bool:
        """Delete a repository secret."""
        url = f"{self.base_url}/actions/secrets/{name}"
        response = requests.delete(url, headers=self.headers)
        return response.status_code == 204
    
    def verify_token(self) -> bool:
        """Verify the token has necessary permissions."""
        try:
            response = requests.get(
                f"https://api.github.com/repos/{self.owner}/{self.repo}",
                headers=self.headers
            )
            if response.status_code == 404:
                print(f"❌ Repository {self.owner}/{self.repo} not found")
                return False
            elif response.status_code == 401:
                print("❌ Invalid GitHub token")
                return False
            elif response.status_code == 403:
                print("❌ Token lacks necessary permissions")
                return False
            return True
        except Exception as e:
            print(f"❌ Connection error: {e}")
            return False


def sanitize_secret_name(name: str) -> str:
    """
    Convert secret name to valid GitHub secret name format.
    
    GitHub secret names:
    - Can only contain alphanumeric characters and underscores
    - Cannot start with a number
    - Cannot start with GITHUB_ prefix
    
    NOTE: We keep the DG_ prefix and __ separators for .NET compatibility.
    The env var name in GitHub should match what DeployGuard generated.
    Example: DG_AzureB2C__client_secret
    """
    # Keep the name as-is (it should already be properly formatted by DeployGuard)
    # Just ensure it's valid for GitHub
    
    # Replace invalid characters with underscores (keep __ for .NET)
    sanitized = ""
    for char in name:
        if char.isalnum() or char == "_":
            sanitized += char
        else:
            sanitized += "_"
    
    # Ensure doesn't start with number
    if sanitized and sanitized[0].isdigit():
        sanitized = "_" + sanitized
    
    # Ensure doesn't start with GITHUB_
    if sanitized.startswith("GITHUB_"):
        sanitized = "DG_" + sanitized
    
    return sanitized


def load_secrets_from_json(filepath: str) -> list[dict]:
    """Load secrets from the DeployGuard scan JSON file."""
    with open(filepath, 'r') as f:
        data = json.load(f)
    return data.get("secrets", [])


def extract_clean_value(raw_value: str) -> str:
    """
    Extract the actual secret value, removing any JSON key prefixes.
    
    Example: 'Key": "actualvalue"' -> 'actualvalue'
    """
    import re
    
    # Pattern: key": "value" or key": 'value'
    match = re.search(r'^\w+["\']?\s*:\s*["\'](.+?)["\']?$', raw_value)
    if match:
        return match.group(1)
    
    # Pattern: key = "value"
    match = re.search(r'^\w+\s*=\s*["\'](.+?)["\']$', raw_value)
    if match:
        return match.group(1)
    
    # Return as-is if no pattern matches
    return raw_value


def main():
    parser = argparse.ArgumentParser(
        description="Push secrets to GitHub Repository/Environment Secrets"
    )
    parser.add_argument(
        "--repo", "-r",
        required=True,
        help="GitHub repository in format 'owner/repo'"
    )
    parser.add_argument(
        "--secrets-file", "-f",
        required=True,
        help="Path to DeployGuard secrets JSON file"
    )
    parser.add_argument(
        "--environment", "-e",
        help="GitHub environment name (e.g., 'production', 'staging')"
    )
    parser.add_argument(
        "--token", "-t",
        help="GitHub PAT (or set GITHUB_TOKEN env var)"
    )
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Show what would be done without making changes"
    )
    parser.add_argument(
        "--prefix", "-p",
        default="",
        help="Prefix to add to all secret names"
    )
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Confirm each secret before pushing"
    )
    
    args = parser.parse_args()
    
    # Get token
    token = args.token or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("❌ GitHub token required. Set GITHUB_TOKEN env var or use --token")
        sys.exit(1)
    
    # Parse repo
    if "/" not in args.repo:
        print("❌ Repository must be in format 'owner/repo'")
        sys.exit(1)
    owner, repo = args.repo.split("/", 1)
    
    # Load secrets
    if not os.path.exists(args.secrets_file):
        print(f"❌ Secrets file not found: {args.secrets_file}")
        sys.exit(1)
    
    secrets = load_secrets_from_json(args.secrets_file)
    if not secrets:
        print("❌ No secrets found in file")
        sys.exit(1)
    
    print("=" * 70)
    print("🔐 GitHub Secrets Push Tool")
    print("=" * 70)
    print(f"Repository: {owner}/{repo}")
    print(f"Secrets file: {args.secrets_file}")
    print(f"Environment: {args.environment or 'Repository-level'}")
    print(f"Total secrets: {len(secrets)}")
    print(f"Dry run: {args.dry_run}")
    print("=" * 70)
    
    # Initialize manager
    manager = GitHubSecretsManager(token, owner, repo)
    
    if not args.dry_run:
        print("\n🔍 Verifying GitHub access...")
        if not manager.verify_token():
            sys.exit(1)
        print("   ✅ Token verified\n")
    
    # Process secrets
    success_count = 0
    skip_count = 0
    fail_count = 0
    
    # Track unique secrets (avoid duplicates)
    processed = set()
    
    for secret in secrets:
        env_var = secret.get("env_var", "")
        raw_value = secret.get("value", "")
        secret_type = secret.get("type", "unknown")
        
        # Skip if no value
        if not raw_value:
            continue
        
        # Create sanitized name
        base_name = sanitize_secret_name(env_var)
        if args.prefix:
            name = f"{args.prefix}_{base_name}"
        else:
            name = base_name
        
        # Skip duplicates
        if name in processed:
            continue
        processed.add(name)
        
        # Extract clean value
        clean_value = extract_clean_value(raw_value)
        
        # Display info
        display_value = clean_value[:30] + "..." if len(clean_value) > 30 else clean_value
        print(f"\n📦 {name}")
        print(f"   Type: {secret_type}")
        print(f"   Value: {display_value}")
        
        if args.interactive:
            response = input("   Push this secret? [y/N]: ").strip().lower()
            if response != 'y':
                print("   ⏭️  Skipped")
                skip_count += 1
                continue
        
        if args.dry_run:
            print("   🔄 Would push (dry-run)")
            success_count += 1
        else:
            if args.environment:
                success = manager.create_or_update_environment_secret(
                    args.environment, name, clean_value
                )
            else:
                success = manager.create_or_update_repo_secret(name, clean_value)
            
            if success:
                print("   ✅ Pushed successfully")
                success_count += 1
            else:
                fail_count += 1
    
    # Summary
    print("\n" + "=" * 70)
    print("📊 Summary")
    print("=" * 70)
    print(f"✅ Successful: {success_count}")
    print(f"⏭️  Skipped:    {skip_count}")
    print(f"❌ Failed:     {fail_count}")
    
    if not args.dry_run and success_count > 0:
        print(f"\n🎉 Secrets are now available in your GitHub repository!")
        if args.environment:
            print(f"   Access them in GitHub Actions with environment: {args.environment}")
        print("\n   Example usage in GitHub Actions:")
        print("   ```yaml")
        print("   env:")
        print(f"     DATABASE_PASSWORD: ${{{{ secrets.{list(processed)[0] if processed else 'SECRET_NAME'} }}}}")
        print("   ```")


if __name__ == "__main__":
    main()
