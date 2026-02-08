#!/usr/bin/env python3
"""
Execute cleanup on the existing mirror clone.
"""

import sys
import os
import shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from deployguard.core.history_cleaner import GitHistoryCleaner
from deployguard.core.scanner import SecretScanner

ORIGINAL_REPO_PATH = "/Users/salginci/Source/GITHUB/deployguard_test_repo"
MIRROR_CLONE_PATH = "/Users/salginci/Source/GITHUB/deployguard_test_repo_mirror.git"

def main():
    print("=" * 70)
    print("🚀 DeployGuard Cleanup Execution")
    print("=" * 70)
    print()
    
    # Initialize
    print("🔧 Initializing...")
    scanner = SecretScanner()
    cleaner = GitHistoryCleaner(scanner)
    
    print(f"   git-filter-repo available: {cleaner._git_filter_repo_available}")
    print()
    
    # Step 0: Create fresh mirror clone
    print("📍 STEP 0: Creating fresh mirror clone...")
    if os.path.exists(MIRROR_CLONE_PATH):
        print(f"   Removing existing mirror...")
        shutil.rmtree(MIRROR_CLONE_PATH)
    
    cleaner.create_mirror_clone(ORIGINAL_REPO_PATH, MIRROR_CLONE_PATH)
    print(f"   ✅ Mirror clone created")
    print()
    
    # Step 1: Scan secrets (we need them again for cleanup)
    print("📍 STEP 1: Scanning secrets...")
    secrets = cleaner.scan_git_history(MIRROR_CLONE_PATH, include_all_branches=True)
    print(f"   Found {len(secrets)} secrets")
    
    # Step 2: Scan large files
    print()
    print("📍 STEP 2: Scanning large files...")
    large_files = cleaner.scan_large_files(MIRROR_CLONE_PATH, max_size_mb=100.0)
    print(f"   Found {len(large_files)} large files")
    
    # Step 3: Execute cleanup
    print()
    print("📍 STEP 3: Executing cleanup...")
    print("   ⚠️  This will rewrite git history!")
    print()
    
    result = cleaner.full_cleanup(
        repo_path=MIRROR_CLONE_PATH,
        secrets=secrets,
        large_files=large_files,
        use_env_vars=True,
        dry_run=False,  # ACTUALLY DO IT
        show_progress=True,
    )
    
    print()
    print("=" * 70)
    print("✅ CLEANUP COMPLETE")
    print("=" * 70)
    print()
    print(f"   Secrets removed: {result.secrets_removed}/{result.secrets_found}")
    print(f"   Large files removed: {result.large_files_removed}/{result.large_files_found}")
    print(f"   Commits rewritten: {result.commits_rewritten}")
    
    if result.errors:
        print()
        print("⚠️  Errors:")
        for err in result.errors[:10]:
            print(f"      • {err[:200]}...")
    
    print()
    print("📍 NEXT STEPS:")
    print()
    print("   To push the cleaned repository:")
    print()
    print(f"   cd {MIRROR_CLONE_PATH}")
    print("   git remote set-url origin <YOUR_NEW_REMOTE_URL>")
    print("   git push --mirror --force")
    print()
    print("   ⚠️  All team members must re-clone after push!")
    print()
    print()

if __name__ == "__main__":
    main()
