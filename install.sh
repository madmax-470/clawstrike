#!/usr/bin/env bash
# install.sh — ClawStrike OS automated installer
# Supports: Debian 12 / Ubuntu 22.04 — idempotent

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${BLUE}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

INSTALL_DIR="/opt/clawstrike"
SERVICE_NAME="clawstrike"
REPO_URL="https://github.com/madmax-470/clawstrike.git"
VENV_DIR="$INSTALL_DIR/venv"

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash install.sh"

# ─── 1. System dependencies ───────────────────────────────────────────────────
step "Updating apt and installing system dependencies"
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip \
    git curl wget gnupg2 lsb-release software-properties-common
success "System dependencies installed"

# ─── 2. Pentest tools ─────────────────────────────────────────────────────────
# To add/remove a tool: edit this list and the REGISTRY in agent/core/tools_registry.py
step "Installing pentest tools"
apt-get update -qq

# nmap — network discovery and port scanning (CRITICAL)
apt-get install -y -qq nmap

# gobuster — directory and DNS brute-forcing
apt-get install -y -qq gobuster

# sqlmap — automated SQL injection detection and exploitation
apt-get install -y -qq sqlmap

# nikto — web server vulnerability scanner
apt-get install -y -qq nikto

# hydra — credential brute-forcing (SSH, FTP, HTTP, etc.)
apt-get install -y -qq hydra

# zaproxy — OWASP ZAP web application active scanner
apt-get install -y -qq zaproxy

# mitmproxy — interactive HTTPS traffic interception proxy
apt-get install -y -qq mitmproxy

# ffuf — fast web fuzzer for content discovery
apt-get install -y -qq ffuf

# ssh-audit — SSH server configuration and cipher auditing
apt-get install -y -qq ssh-audit

# enum4linux — SMB/NetBIOS enumeration for Windows/Samba hosts
apt-get install -y -qq enum4linux

# netexec — network service enumeration and credential testing (CrackMapExec successor)
apt-get install -y -qq netexec
success "nmap  gobuster  sqlmap  nikto  hydra  zaproxy  mitmproxy — installed"

# Metasploit is not in default Debian/Ubuntu repos — use Rapid7's apt repo
if ! command -v msfconsole &>/dev/null; then
    info "Adding Rapid7 apt repository for Metasploit Framework…"
    wget -qO /tmp/msf-key.gpg https://apt.metasploit.com/metasploit-framework.gpg.key
    gpg --dearmor < /tmp/msf-key.gpg > /usr/share/keyrings/metasploit-framework.gpg
    rm /tmp/msf-key.gpg
    echo "deb [signed-by=/usr/share/keyrings/metasploit-framework.gpg arch=amd64] \
https://apt.metasploit.com/ $(lsb_release -cs) main" \
        > /etc/apt/sources.list.d/metasploit-framework.list
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq metasploit-framework
    success "Metasploit Framework installed"
else
    success "Metasploit already present — skipping"
fi

# ─── 3. Clone / update repo ───────────────────────────────────────────────────
step "Setting up ClawStrike repository"
if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Repository already cloned — pulling latest"
    git -C "$INSTALL_DIR" pull --ff-only
else
    git clone "$REPO_URL" "$INSTALL_DIR"
fi
success "Repository ready at $INSTALL_DIR"

# ─── 4. Python venv + requirements ───────────────────────────────────────────
step "Setting up Python virtual environment"
[[ ! -d "$VENV_DIR" ]] && python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
success "Python dependencies installed"

# ─── 5. Configure API key + model ─────────────────────────────────────────────
step "Configuring ClawStrike"
echo ""
echo -e "${BOLD}Select AI provider:${RESET}"
echo "  1) Anthropic (Claude)"
echo "  2) OpenAI (GPT)"
echo "  3) Ollama (local)"
read -rp "Choice [1-3, default=1]: " PROVIDER_CHOICE
PROVIDER_CHOICE="${PROVIDER_CHOICE:-1}"

case "$PROVIDER_CHOICE" in
    2) PROVIDER="openai";    DEFAULT_MODEL="gpt-4o" ;;
    3) PROVIDER="ollama";    DEFAULT_MODEL="llama3.1" ;;
    *) PROVIDER="anthropic"; DEFAULT_MODEL="claude-opus-4-6" ;;
esac

read -rp "Model [default: $DEFAULT_MODEL]: " MODEL
MODEL="${MODEL:-$DEFAULT_MODEL}"

if [[ "$PROVIDER" == "ollama" ]]; then
    read -rp "Ollama base URL [default: http://localhost:11434/v1]: " OLLAMA_URL
    OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434/v1}"
    API_KEY="ollama"
else
    read -rsp "API key for $PROVIDER: " API_KEY; echo ""
    [[ -z "$API_KEY" ]] && error "API key cannot be empty"
fi

# Pass values via env vars so special characters in API keys are handled safely
CLAWSTRIKE_PROVIDER="$PROVIDER" \
CLAWSTRIKE_MODEL="$MODEL" \
CLAWSTRIKE_API_KEY="$API_KEY" \
CLAWSTRIKE_OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434/v1}" \
CLAWSTRIKE_CONFIG="$INSTALL_DIR/config.yaml" \
"$VENV_DIR/bin/python3" - <<'PYEOF'
import yaml, os

path = os.environ["CLAWSTRIKE_CONFIG"]
with open(path) as f:
    cfg = yaml.safe_load(f)

provider = os.environ["CLAWSTRIKE_PROVIDER"]
model    = os.environ["CLAWSTRIKE_MODEL"]
api_key  = os.environ["CLAWSTRIKE_API_KEY"]

cfg["provider"] = provider
if provider == "anthropic":
    cfg["anthropic"]["model"]   = model
    cfg["anthropic"]["api_key"] = api_key
elif provider == "openai":
    cfg["openai"]["model"]   = model
    cfg["openai"]["api_key"] = api_key
elif provider == "ollama":
    cfg["ollama"]["model"]    = model
    cfg["ollama"]["base_url"] = os.environ["CLAWSTRIKE_OLLAMA_URL"]

with open(path, "w") as f:
    yaml.dump(cfg, f, default_flow_style=False, allow_unicode=True)
PYEOF
success "config.yaml updated (provider=$PROVIDER, model=$MODEL)"

# ─── 6. Systemd service ───────────────────────────────────────────────────────
step "Creating systemd service"
cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=ClawStrike AI Penetration Testing Agent
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
Environment=PYTHONPATH=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/python3 -m agent.core.loop
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}.service"
success "Service '${SERVICE_NAME}' created and enabled"

# ─── 7. System-wide launcher ──────────────────────────────────────────────────
step "Installing system-wide launcher"
cat > /usr/local/bin/clawstrike <<EOF
#!/usr/bin/env bash
cd $INSTALL_DIR
PYTHONPATH=$INSTALL_DIR exec $VENV_DIR/bin/python3 -m agent.core.loop "\$@"
EOF
chmod +x /usr/local/bin/clawstrike
success "Launcher installed — run 'clawstrike' or 'sudo clawstrike' from anywhere"

# ─── 8. Success banner ────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║        ClawStrike OS — Installation Complete!    ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${BOLD}Installed to:${RESET}  $INSTALL_DIR"
echo -e "  ${BOLD}Provider:${RESET}      $PROVIDER  ($MODEL)"
echo -e "  ${BOLD}Service:${RESET}       ${SERVICE_NAME}.service (enabled on boot)"
echo ""
echo -e "${CYAN}${BOLD}Start ClawStrike:${RESET}"
echo ""
echo -e "  ${YELLOW}cd $INSTALL_DIR && $VENV_DIR/bin/python3 agent/core/loop.py${RESET}"
echo ""
echo -e "${CYAN}${BOLD}Service commands:${RESET}"
echo -e "  ${YELLOW}sudo systemctl start  $SERVICE_NAME${RESET}"
echo -e "  ${YELLOW}sudo journalctl -u $SERVICE_NAME -f${RESET}"
echo ""
echo -e "${CYAN}${BOLD}Metasploit RPC (optional — needed for msf_search / msf_exploit):${RESET}"
echo -e "  ${YELLOW}msfrpcd -P clawstrike -p 55553 -S${RESET}"
echo -e "  [dim](ClawStrike will start this automatically when needed)[/dim]"
echo ""
echo -e "${CYAN}${BOLD}Update later:${RESET}"
echo -e "  ${YELLOW}cd $INSTALL_DIR && git pull && $VENV_DIR/bin/pip install -r requirements.txt -q${RESET}"
echo ""
