#!/bin/bash

# K8sMatrixWarden Environment Setup Script
# Detects Python versions, checks requirements, and sets up MCP environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}K8sMatrixWarden Setup Wizard${NC}"
echo -e "${BLUE}================================${NC}\n"

# ============================================================================
# Step 1: Extract Python requirement from pyproject.toml
# ============================================================================

echo -e "${YELLOW}[1/5] Reading Python requirements from pyproject.toml...${NC}"

if [ ! -f "$PROJECT_ROOT/pyproject.toml" ]; then
    echo -e "${RED}ERROR: pyproject.toml not found${NC}"
    exit 1
fi

# Extract requires-python from pyproject.toml (e.g., ">=3.10")
PYTHON_REQ=$(grep -oP 'requires-python = "\K[^"]+' "$PROJECT_ROOT/pyproject.toml" 2>/dev/null || echo ">=3.10")

echo -e "${GREEN}✓ Project requires: Python ${PYTHON_REQ}${NC}\n"

# ============================================================================
# Step 2: Find all available Python versions
# ============================================================================

echo -e "${YELLOW}[2/5] Scanning for available Python versions...${NC}"

find_python_versions() {
    local pythons=()

    # Common locations to search
    local search_paths=(
        "/usr/bin"
        "/usr/local/bin"
        "/opt/homebrew/bin"
        "/opt/python*/bin"
        "$HOME/.pyenv/versions/*/bin"
        "/usr/local/opt/python*/bin"
    )

    for dir in "${search_paths[@]}"; do
        if [ -d "$dir" ]; then
            while IFS= read -r python_exe; do
                if [[ -x "$python_exe" ]] && [[ "$python_exe" =~ python[0-9] ]]; then
                    pythons+=("$python_exe")
                fi
            done < <(find "$dir" -maxdepth 1 -name "python*" 2>/dev/null)
        fi
    done

    # Also check which command
    for v in 3.14 3.13 3.12 3.11 3.10 3.9 3.8; do
        if command -v "python${v}" &>/dev/null; then
            pythons+=("$(command -v "python${v}")")
        fi
    done

    # Remove duplicates and sort
    printf '%s\n' "${pythons[@]}" | sort -u
}

FOUND_PYTHONS=$(find_python_versions)

if [ -z "$FOUND_PYTHONS" ]; then
    echo -e "${RED}ERROR: No Python installations found${NC}"
    exit 1
fi

echo -e "${GREEN}Found the following Python installations:${NC}"

declare -a PYTHON_ARRAY
declare -a SUITABLE_PYTHONS

index=0
while IFS= read -r python_exe; do
    if [ -x "$python_exe" ]; then
        version=$("$python_exe" --version 2>&1 | awk '{print $2}')
        PYTHON_ARRAY[$index]="$python_exe"

        # Check if version >= 3.10 (suitable for this project)
        major=$(echo "$version" | cut -d. -f1)
        minor=$(echo "$version" | cut -d. -f2)

        if [ "$major" -eq 3 ] && [ "$minor" -ge 10 ]; then
            echo -e "  ${GREEN}✓${NC} $index) $python_exe (Python $version) ${GREEN}[SUITABLE]${NC}"
            SUITABLE_PYTHONS+=("$index")
        else
            echo -e "  ${RED}✗${NC} $index) $python_exe (Python $version) - TOO OLD (need >=3.10)"
        fi
        ((index++))
    fi
done <<< "$FOUND_PYTHONS"

if [ ${#SUITABLE_PYTHONS[@]} -eq 0 ]; then
    echo -e "${RED}ERROR: No Python version >= 3.10 found${NC}"
    echo "Please install Python 3.10 or higher"
    exit 1
fi

echo ""

# ============================================================================
# Step 3: Select Python version (prefer latest)
# ============================================================================

echo -e "${YELLOW}[3/5] Selecting suitable Python version...${NC}"

SELECTED_PYTHON_IDX=${SUITABLE_PYTHONS[-1]}  # Last (newest) suitable version
SELECTED_PYTHON="${PYTHON_ARRAY[$SELECTED_PYTHON_IDX]}"
SELECTED_VERSION=$("$SELECTED_PYTHON" --version 2>&1 | awk '{print $2}')

echo -e "${GREEN}✓ Selected: $SELECTED_PYTHON (Python $SELECTED_VERSION)${NC}\n"

# ============================================================================
# Step 4: Check required packages
# ============================================================================

echo -e "${YELLOW}[4/5] Checking required packages...${NC}"

check_package() {
    local package=$1
    local python_exe=$2

    if "$python_exe" -c "import $package" 2>/dev/null; then
        return 0  # Package found
    else
        return 1  # Package not found
    fi
}

# Packages required for MCP
REQUIRED_PACKAGES=("mcp")
MISSING_PACKAGES=()

for pkg in "${REQUIRED_PACKAGES[@]}"; do
    if check_package "$pkg" "$SELECTED_PYTHON"; then
        echo -e "  ${GREEN}✓${NC} $pkg is installed"
    else
        echo -e "  ${RED}✗${NC} $pkg is ${RED}NOT${NC} installed"
        MISSING_PACKAGES+=("$pkg")
    fi
done

echo ""

# ============================================================================
# Step 5: Show summary and ask for confirmation
# ============================================================================

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}Setup Summary${NC}"
echo -e "${BLUE}================================${NC}\n"

echo -e "Python Selection:"
echo -e "  Executable: ${GREEN}$SELECTED_PYTHON${NC}"
echo -e "  Version:    ${GREEN}$SELECTED_VERSION${NC}"
echo -e "  Requirement: $PYTHON_REQ ${GREEN}✓${NC}"
echo ""

echo -e "Packages to Install:"
if [ ${#MISSING_PACKAGES[@]} -eq 0 ]; then
    echo -e "  ${GREEN}All required packages are installed${NC}"
else
    for pkg in "${MISSING_PACKAGES[@]}"; do
        echo -e "  - ${YELLOW}$pkg${NC}"
    done
fi

echo ""
echo -e "MCP Configuration Files to Update:"
echo -e "  - .vscode/mcp.json"
echo -e "  - .cursor/mcp.json (if exists)"
echo ""

echo -e "Files to Clean Up:"
echo -e "  - .venv_check/ (will be added to .gitignore)"
echo ""

# Ask for confirmation
echo -n -e "${YELLOW}Proceed with setup? (yes/no): ${NC}"
read -r confirmation

if [[ "$confirmation" != "yes" && "$confirmation" != "y" ]]; then
    echo -e "${RED}Setup cancelled${NC}"
    exit 0
fi

echo ""

# ============================================================================
# Installation
# ============================================================================

echo -e "${YELLOW}Installing required packages...${NC}"

if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
    "$SELECTED_PYTHON" -m pip install --upgrade pip
    for pkg in "${MISSING_PACKAGES[@]}"; do
        echo -e "  Installing ${YELLOW}$pkg${NC}..."
        "$SELECTED_PYTHON" -m pip install "$pkg"
    done
    echo -e "${GREEN}✓ Packages installed${NC}\n"
else
    echo -e "${GREEN}✓ All packages already installed${NC}\n"
fi

# ============================================================================
# Update MCP Configuration Files
# ============================================================================

echo -e "${YELLOW}Updating MCP configuration files...${NC}"

update_mcp_config() {
    local config_file=$1

    if [ -f "$config_file" ]; then
        # Create backup
        cp "$config_file" "${config_file}.backup"

        # Update the command with explicit Python path
        # Use sed to replace the "command" line
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            sed -i '' 's|"command": "[^"]*python[^"]*"|"command": "'$SELECTED_PYTHON'"|g' "$config_file"
        else
            # Linux
            sed -i 's|"command": "[^"]*python[^"]*"|"command": "'$SELECTED_PYTHON'"|g' "$config_file"
        fi

        echo -e "  ${GREEN}✓${NC} Updated $config_file"
        echo -e "     Backup saved: ${config_file}.backup"
    fi
}

update_mcp_config "$PROJECT_ROOT/.vscode/mcp.json"

if [ -d "$PROJECT_ROOT/.cursor" ]; then
    update_mcp_config "$PROJECT_ROOT/.cursor/mcp.json"
fi

echo ""

# ============================================================================
# Update .gitignore
# ============================================================================

echo -e "${YELLOW}Updating .gitignore...${NC}"

if ! grep -q ".venv_check/" "$PROJECT_ROOT/.gitignore"; then
    echo "" >> "$PROJECT_ROOT/.gitignore"
    echo "# Virtual environments (auto-generated by setup-env.sh)" >> "$PROJECT_ROOT/.gitignore"
    echo ".venv_check/" >> "$PROJECT_ROOT/.gitignore"
    echo -e "  ${GREEN}✓${NC} Added .venv_check/ to .gitignore"
else
    echo -e "  ${GREEN}✓${NC} .venv_check/ already in .gitignore"
fi

echo ""

# ============================================================================
# Verification
# ============================================================================

echo -e "${YELLOW}Verifying setup...${NC}"

# Test MCP import
if "$SELECTED_PYTHON" -c "import mcp; print(f'MCP version: {mcp.__version__}')" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} MCP is working correctly"
else
    echo -e "  ${YELLOW}⚠${NC}  MCP import test failed"
fi

echo ""

# ============================================================================
# Final Summary
# ============================================================================

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Setup Complete!${NC}"
echo -e "${GREEN}================================${NC}\n"

echo -e "Your environment is ready:"
echo -e "  Python: ${GREEN}$SELECTED_PYTHON${NC} (v$SELECTED_VERSION)"
echo -e "  MCP: ${GREEN}installed${NC}"
echo -e "  Config: ${GREEN}updated${NC}"
echo ""

echo "Next steps:"
echo "  1. Restart your editor (VSCode/Cursor)"
echo "  2. Run: claude code --config"
echo "  3. Test MCP connection"
echo ""

echo -e "${YELLOW}Optional: Run cleanup${NC}"
echo "  rm -rf .venv_check/  # Remove old venv (safe now that .gitignore is updated)"
