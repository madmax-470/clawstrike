# ClawStrike OS — Project TODO

## Features

### Feature 1 — Engagement Memory ✅
- [x] Create `agent/memory/store.py` with `save_engagement()`
- [x] Write markdown files to `/engagements/<target>_<timestamp>.md`
- [x] Wire into `agent/core/loop.py` — saves after every scan

### Feature 2 — Gobuster Integration ✅
- [x] Create `agent/tools/gobuster.py` (same pattern as nmap.py)
- [x] Parse found paths from gobuster output
- [x] Handle gobuster-not-installed gracefully
- [x] Add `gobuster_scan` tool to `handle_tool_call` in loop.py
- [x] Update SYSTEM_PROMPT with gobuster tool definition
- [x] Auto-hint agent to suggest gobuster when port 80/443 found

### Feature 3 — Auto Chaining ✅
- [x] Create `agent/core/planner.py`
- [x] Port 22 open → suggest ssh-audit
- [x] Port 80/443/8080/8443 open → automatically run gobuster
- [x] Port 3306 open → suggest mysql enumeration
- [x] Extra: Port 5432 → suggest psql enum, 6379 → redis-cli, 27017 → mongosh, 21 → ftp-anon, 25 → smtp-enum
- [x] Wire planner into loop.py post-nmap

---

### Feature 4 — Report Generation ✅
- [x] Install python-docx
- [x] Create `agent/reports/generator.py`
- [x] Parse all engagement .md files for a target
- [x] CERT-In formatted .docx: cover page, exec summary, findings table with CVSS
- [x] PoC steps per service (ssh, http, mysql, ftp, smb, rdp, redis, etc.)
- [x] Recommendations section
- [x] Agent analysis section
- [x] Wire `report <target>` command into loop.py (bypasses LLM, direct call)
- [x] Saves to `reports/<target>_<timestamp>.docx`

### Feature 6 — SQLMap Integration ✅
- [x] Create `agent/tools/sqlmap.py` (same pattern as nmap/gobuster)
- [x] Parse vulnerable params and databases from sqlmap output
- [x] Handle sqlmap-not-installed gracefully with install instructions
- [x] Add `sqlmap_scan` to `handle_tool_call` in loop.py
- [x] Add `TOOL: sqlmap_scan` to SYSTEM_PROMPT (suggest only, never auto-run)
- [x] Planner suggests sqlmap when port 80/443/8080 found open

### Feature 7 — Gobuster Auto-trigger ✅ (already built in Feature 2/3)
- [x] Gobuster auto-runs via planner when port 80/443/8080/8443 found
- [x] Results appended to TOOL_RESULT and fed to agent for analysis
- [x] Engagement saved after every nmap scan (includes gobuster context)

### Feature 8 — Scope Enforcement ✅
- [x] Create `agent/core/scope.py` — `ScopeManager` class
- [x] `scope <cidr>` — set scope (IPs, CIDRs, hostnames all supported)
- [x] `scope show` — display current scope
- [x] `scope clear` — reset scope
- [x] `_scope_check()` gate in `handle_tool_call` — blocks nmap, gobuster, sqlmap
- [x] Planner auto-run (gobuster) also scope-gated
- [x] Scope written to every engagement markdown file
- [x] Startup banner updated with scope commands

### Feature 5 — BYOM Config System ✅
- [x] Install pyyaml
- [x] Create `config.yaml` in project root
- [x] Create `agent/core/config.py` with `load_config()`, `build_client()`, `chat()`
- [x] Support anthropic / openai / ollama providers
- [x] Wire into loop.py — replaced all hardcoded client/model calls
- [x] Startup banner shows active provider and model

---

## Backlog / Ideas
- [ ] gobuster wordlist config (env var or CLI flag)
- [ ] ssh-audit tool integration (`agent/tools/ssh_audit.py`)
- [ ] mysql enumeration tool (`agent/tools/mysql_enum.py`)
- [ ] engagement report HTML export
- [ ] multi-target batch scanning
