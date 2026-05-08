#!/bin/bash
# install_p0_tools.sh - Automated deployment for Mimikri P0 Arsenal
set -e

TOOLS_DIR="$HOME/.local/share/osint-ultimate/tools"
mkdir -p "$TOOLS_DIR"

echo "🚀 Mimikri P0 Arsenal Installer: Activating..."

# Helper function to install
install_tool() {
    local name=$1
    local repo=$2
    local dir="$TOOLS_DIR/$name"
    
    if [ ! -d "$dir" ]; then
        echo "📥 Cloning $name..."
        git clone "$repo" "$dir" || echo "❌ Failed to clone $name"
    else
        echo "✅ $name already exists, updating..."
        cd "$dir" && git pull && cd -
    fi
    
    if [ -d "$dir" ]; then
        cd "$dir"
        if [ -f "requirements.txt" ]; then
            echo "📦 Installing requirements for $name..."
            python3 -m pip install -r requirements.txt --break-system-packages || echo "⚠️ Pip failed for $name requirements"
        fi
        cd -
    fi
}

# 1. SSRFmap
install_tool "ssrfmap" "https://github.com/swisskyrepo/SSRFmap"

# 2. Gopherus (Python 3 compatible)
install_tool "gopherus" "https://github.com/Esonhugh/Gopherus3"

# 3. nosqli (Go-based, replacement for NoSQLMap)
echo "📦 Installing nosqli (Go)..."
go install github.com/Charlie-belmer/nosqli@latest

# 4. Ghauri (Python)
echo "📦 Installing ghauri (Python)..."
python3 -m pip install git+https://github.com/r0oth3x49/ghauri.git --break-system-packages || true

# 5. s3scanner (Python)
echo "📦 Installing s3scanner (Python)..."
python3 -m pip install s3scanner --break-system-packages || true

echo "✨ P0 Tools Installation Completed."
