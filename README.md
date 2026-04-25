# ClawStrike OS

An agentic AI pentesting environment powered by Claude (or any OpenAI-compatible model). ClawStrike runs a conversational loop where you describe a target and the agent autonomously plans, executes, and chains security tools — then feeds the results back to the LLM for analysis.

---

## What It Does

- **Reconnaissance** — nmap port scans with automatic service detection
- **Web enumeration** — gobuster directory brute-force, auto-triggered on ports 80/443
- **Web vulnerability scanning** — nikto, auto-triggered on ports 80/443
- **SQL injection testing** — sqlmap, suggest-only (never auto-run)
- **Credential brute-forcing** — hydra, explicit user confirmation required every time
- **Auto chaining** — planner fires follow-up tools based on what nmap finds
- **Scope enforcement** — all tool calls are gated against a defined CIDR/IP scope
- **Engagement memory** — every scan saved to `/engagements/` as markdown
- **Session summary** — `summary` command reads all engagement files and gives a full status update
- **Report generation** — CERT-In formatted `.docx` reports with CVSS scores and PoC steps
- **BYOM** — swap between Anthropic, OpenAI, or Ollama in one config line

---

## Requirements

**Python:** 3.11+

**External tools** (must be on PATH):

| Tool | Install |
|------|---------|
| nmap | `brew install nmap` / `sudo apt install nmap` |
| gobuster | `brew install gobuster` / `sudo apt install gobuster` |
| sqlmap | `brew install sqlmap` / `sudo apt install sqlmap` |
| nikto | `brew install nikto` / `sudo apt install nikto` |
| hydra | `brew install hydra` / `sudo apt install hydra` |

---

## Install

```bash
git clone https://github.com/YOUR_USERNAME/clawstrike.git
cd clawstrike

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

cp .env.example .env
# edit .env and add your API key
```

**.env format:**

```
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-opus-4-6
```

---

## Configure BYOM

Edit `config.yaml` to switch providers:

```yaml
provider: anthropic   # anthropic | openai | ollama

anthropic:
  api_key: ""         # or set ANTHROPIC_API_KEY in .env
  model: claude-opus-4-6

openai:
  api_key: ""         # or set OPENAI_API_KEY in .env
  model: gpt-4o

ollama:
  base_url: http://localhost:11434
  model: llama3
  api_key: ollama
```

Set `provider:` to `anthropic`, `openai`, or `ollama` — no other changes needed. The active provider and model are shown in the startup banner.

---

## Usage

```bash
source venv/bin/activate
python -m agent.core.loop
```

### Built-in commands

| Command | Description |
|---------|-------------|
| `scope <cidr>` | Set target scope — accepts IPs, CIDRs, hostnames |
| `scope show` | Display current scope |
| `scope clear` | Remove scope restrictions |
| `summary` | Full status update across all engagement files |
| `summary <target>` | Status update for a specific target |
| `report <target>` | Generate a CERT-In `.docx` report for a target |
| `exit` / `quit` | End session |

### Example session

```
claw@strike → scope 192.168.1.0/24
claw@strike → scan 192.168.1.10 with version detection
claw@strike → brute-force SSH on 192.168.1.10 with user admin
claw@strike → summary 192.168.1.10
claw@strike → report 192.168.1.10
```

### Tool calls

The agent emits tool calls automatically. You can also ask directly:

```
scan 10.0.0.5 -sV -p 1-1024
run gobuster on 10.0.0.5
test 10.0.0.5/login.php for SQL injection
run nikto on 10.0.0.5
brute-force FTP on 10.0.0.5 with rockyou
```

Hydra always shows the exact command and requires `y` confirmation before running.

---

## Engagement Files & Reports

**Engagements** are saved automatically after every nmap scan:

```
engagements/
  192.168.1.10_20260421_113856.md
```

Each file contains the target, timestamp, scope, open ports table, and the agent's full analysis.

**Reports** are generated on demand with `report <target>`:

```
reports/
  192.168.1.10_20260421_120000.docx
```

Reports include: executive summary, CVSS findings table, per-service PoC steps, and recommendations.

---

## Project Structure

```
clawstrike/
├── agent/
│   ├── core/
│   │   ├── config.py       # BYOM provider config
│   │   ├── loop.py         # main agent loop
│   │   ├── planner.py      # auto-chaining logic
│   │   └── scope.py        # target scope enforcement
│   ├── memory/
│   │   └── store.py        # engagement file I/O
│   ├── reports/
│   │   └── generator.py    # .docx report builder
│   └── tools/
│       ├── nmap.py
│       ├── gobuster.py
│       ├── sqlmap.py
│       ├── nikto.py
│       └── hydra.py
├── engagements/            # auto-saved scan records (gitignored)
├── reports/                # generated .docx reports (gitignored)
├── config.yaml             # provider and tool config
├── requirements.txt
└── .env                    # API keys (gitignored)
```
