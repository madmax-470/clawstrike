#!/bin/bash
# ClawStrike — Full Uninstall Script
# WARNING: Removes everything including data

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo ""
echo -e "${RED}╔══════════════════════════════════════╗${NC}"
echo -e "${RED}║     ClawStrike Full Uninstall        ║${NC}"
echo -e "${RED}╚══════════════════════════════════════╝${NC}"
echo ""
echo -e "${RED}WARNING: This removes EVERYTHING including:${NC}"
echo "  ✗ All ClawStrike code"
echo "  ✗ All engagement data"
echo "  ✗ All reports"
echo "  ✗ Your config and API key"
echo "  ✗ The entire clawstrike directory"
echo ""
echo -e "${YELLOW}This cannot be undone.${NC}"
echo ""

read -p "Type UNINSTALL to confirm complete removal: " confirm
if [ "$confirm" != "UNINSTALL" ]; then
    echo "Cancelled. Nothing was removed."
    exit 0
fi

echo ""
echo "Removing ClawStrike..."

if systemctl is-active --quiet clawstrike 2>/dev/null; then
    systemctl stop clawstrike
    systemctl disable clawstrike
    rm -f /etc/systemd/system/clawstrike.service
    systemctl daemon-reload
    echo "  ✓ systemd service removed"
fi

sed -i '/clawstrike/d' ~/.bashrc 2>/dev/null || true
sed -i '/clawstrike/d' ~/.zshrc 2>/dev/null || true

rm -rf "$PROJECT_DIR"
echo "  ✓ ClawStrike directory removed"

echo ""
echo -e "${GREEN}ClawStrike has been fully uninstalled.${NC}"
echo "Pentest tools (nmap, metasploit etc) were NOT removed."
echo "Remove them manually if needed: apt remove nmap metasploit-framework"
echo ""
