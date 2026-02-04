#!/bin/bash
# Quick scan all your repositories

echo "🛡️  DeployGuard - Repository Security Audit"
echo "============================================"
echo ""

# List of your repositories
REPOS=(
    "/Users/salginci/Source/UOL/Bilyoner_Parser"
    "/Users/salginci/Source/GITHUB/LMS"
    "/Users/salginci/Source/GITHUB/Contest"
    "/Users/salginci/Source/GITHUB/taksi_backend"
    "/Users/salginci/Source/GITHUB/Taksibutonu"
)

# Scan each repository
for repo in "${REPOS[@]}"; do
    if [ -d "$repo" ]; then
        echo ""
        echo "📂 Scanning: $(basename $repo)"
        echo "----------------------------------------"
        python scan_repo.py "$repo" | grep -E "(✅|⚠️|Files Scanned|Total Findings|CRITICAL|HIGH)"
        echo ""
    fi
done

echo ""
echo "✅ Audit Complete!"
