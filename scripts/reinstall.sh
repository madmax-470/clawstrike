#!/bin/bash
# ClawStrike — Reinstall Script
# Wipes everything and does a fresh install
# Preserves: engagements/, reports/ (your data)
# Removes: venv/, agent/, all code

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo ""
echo -e "${RED}╔══════════════════════════════════════╗${NC}"
echo -e "${RED}║     ClawStrike Reinstall Script      ║${NC}"
echo -e "${RED}╚══════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}This will:${NC}"
echo "  ✗ Delete all ClawStrike code and venv"
echo "  ✗ Remove all tool configurations"
echo "  ✓ PRESERVE your engagements/ folder"
echo "  ✓ PRESERVE your reports/ folder"
echo "  ✓ PRESERVE your config.yaml API key"
echo ""
echo -e "${YELLOW}Your engagement data will NOT be deleted.${NC}"
echo ""

read -p "Type REINSTALL to confirm: " confirm
if [ "$confirm" != "REINSTALL" ]; then
    echo "Cancelled."
    exit 0
fi

echo ""
echo -e "${GREEN}Backing up your data...${NC}"

if [ -f "$PROJECT_DIR/config.yaml" ]; then
    cp "$PROJECT_DIR/config.yaml" /tmp/clawstrike_config_backup.yaml
    echo "  ✓ config.yaml backed up"
fi

echo "  ✓ engagements/ preserved"
echo "  ✓ reports/ preserved"

echo ""
echo -e "${GREEN}Removing old installation...${NC}"

rm -rf "$PROJECT_DIR/agent"
rm -rf "$PROJECT_DIR/venv"
rm -rf "$PROJECT_DIR/scripts"
rm -f  "$PROJECT_DIR/requirements.txt"
rm -f  "$PROJECT_DIR/version.py"
rm -f  "$PROJECT_DIR/README.md"
rm -f  "$PROJECT_DIR/install.sh"
echo "  ✓ old code removed"

echo ""
echo -e "${GREEN}Running fresh install...${NC}"
echo ""

curl -fsSL https://raw.githubusercontent.com/rootordie/clawstrike/main/install.sh | bash

if [ -f /tmp/clawstrike_config_backup.yaml ]; then
    cp /tmp/clawstrike_config_backup.yaml "$PROJECT_DIR/config.yaml"
    echo ""
    echo -e "${GREEN}✓ Your API key and config restored${NC}"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     Reinstall complete!              ║${NC}"
echo -e "${GREEN}║     Your data is intact.             ║${NC}"
echo -e "${GREEN}║     Run: clawstrike                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""
