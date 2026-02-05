#!/usr/bin/env python3
"""Debug script to find slow files during scanning."""

from deployguard.core.scanner import SecretScanner
from pathlib import Path
import time
import sys

def main():
    scanner = SecretScanner()
    dir_path = Path('/Users/salginci/Source/GITHUB/deployguard_test_repo')
    
    print(f"Patterns loaded: {len(scanner.patterns)}")
    print(f"Max file size: {scanner.max_file_size} bytes")
    print(f"Skip extensions: {len(scanner.skip_extensions)}")
    print("-" * 60)
    
    total_files = 0
    slow_files = []
    
    for file_path in sorted(dir_path.rglob('*')):
        if not file_path.is_file():
            continue
        
        suffix = file_path.suffix.lower()
        if suffix in scanner.skip_extensions:
            continue
        
        try:
            size = file_path.stat().st_size
            if size > scanner.max_file_size:
                print(f"SKIP (large): {file_path.name} ({size:,} bytes)")
                continue
        except:
            continue
        
        relative = file_path.relative_to(dir_path)
        print(f"Scanning: {relative} ({size:,} bytes)...", end=' ', flush=True)
        
        start = time.time()
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            findings = scanner.scan_file(str(file_path), content)
            elapsed = time.time() - start
            print(f"{elapsed:.2f}s - {len(findings)} findings")
            
            if elapsed > 2:
                slow_files.append((str(relative), elapsed, size))
                print("  ^^^ SLOW FILE!")
            
            total_files += 1
            
        except KeyboardInterrupt:
            print("\nInterrupted!")
            break
        except Exception as e:
            print(f"ERROR: {e}")
    
    print("-" * 60)
    print(f"Total files scanned: {total_files}")
    if slow_files:
        print(f"Slow files (>2s):")
        for name, elapsed, size in slow_files:
            print(f"  {name}: {elapsed:.2f}s ({size:,} bytes)")

if __name__ == "__main__":
    main()
