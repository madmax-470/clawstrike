import subprocess
import threading
from pathlib import Path
from dotenv import load_dotenv
from version import VERSION, BUILD_DATE
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from agent.tools.nmap import scan as nmap_scan, format_for_agent as nmap_format
from agent.tools.gobuster import scan as gobuster_scan, format_for_agent as gobuster_format
from agent.tools.sqlmap import scan as sqlmap_scan, format_for_agent as sqlmap_format
from agent.tools.nikto import scan as nikto_scan, format_for_agent as nikto_format
from agent.tools.hydra import scan as hydra_scan, format_for_agent as hydra_format
from agent.tools.zap import start_scan as zap_scan, format_for_agent as zap_format
from agent.tools.mitm import capture_traffic as mitm_capture, format_for_agent as mitm_format
from agent.tools import metasploit as msf
from agent.core import evidence
from agent.memory.store import save_engagement, load_engagements
from agent.core.planner import decide_next_tools
from agent.core.scope import ScopeManager
from agent.reports.generator import generate_report
from agent.core.config import load_config, ModelConfig, save_workflow_config
from agent.core.router import ModelRouter
from agent.core.checker import check_tools, install_tool, install_missing
from agent.core.exploit_runner import exploit_runner
from agent.core.post_exploit import post_exploiter
from agent.core.session import EngagementSession, LootItem
from agent.core.model_router import ModelRouter as NewModelRouter

load_dotenv()
console = Console()

cfg    = load_config()
scope  = ScopeManager()
current_session = None  # set by _handle_pentest, read by exploit commands

SYSTEM_PROMPT = """You are ClawStrike, an elite agentic AI running inside a
purpose-built pentesting and development Linux environment.

You have access to the following tools:

TOOL: nmap_scan
Use this when the user asks to scan, recon, or enumerate a target.
To call it, respond with exactly this format on its own line:
TOOL_CALL: nmap_scan <target> <flags>
Example: TOOL_CALL: nmap_scan 192.168.1.1 -sV
Example: TOOL_CALL: nmap_scan 127.0.0.1 -sV

TOOL: gobuster_scan
Use this to brute-force directories and files on a web server.
To call it, respond with exactly this format on its own line:
TOOL_CALL: gobuster_scan <target>
Example: TOOL_CALL: gobuster_scan 192.168.1.1
Example: TOOL_CALL: gobuster_scan 10.0.0.5:8080
When port 80 or 443 is found open, always suggest running gobuster_scan.

TOOL: sqlmap_scan
Use this to test a URL for SQL injection vulnerabilities.
Only suggest this when a web port is open AND the user confirms there are login forms or query parameters.
To call it, respond with exactly this format on its own line:
TOOL_CALL: sqlmap_scan <url>
Example: TOOL_CALL: sqlmap_scan http://192.168.1.1/login.php?id=1
Example: TOOL_CALL: sqlmap_scan http://10.0.0.5/search?q=test
Never run sqlmap_scan automatically — always confirm with the user first.

TOOL: nikto_scan
Use this to scan a web server for known vulnerabilities, misconfigurations, and exposed files.
Automatically triggered when port 80 or 443 is found open.
To call it manually, respond with exactly this format on its own line:
TOOL_CALL: nikto_scan <target>
Example: TOOL_CALL: nikto_scan 192.168.1.1
Example: TOOL_CALL: nikto_scan 10.0.0.5 -p 443 -ssl
After nikto runs, analyze all findings and highlight high-severity issues such as outdated software, dangerous HTTP methods, or exposed sensitive paths.

TOOL: zap_scan
Use this to run an OWASP ZAP active scan against a web target (spider + active scan + alert collection).
Automatically triggered when port 80 or 443 is found open alongside nikto.
To call it manually, respond with exactly this format on its own line:
TOOL_CALL: zap_scan <target>
Example: TOOL_CALL: zap_scan http://192.168.1.1
Example: TOOL_CALL: zap_scan http://10.0.0.5:8080
After ZAP runs, highlight High and Medium severity alerts and recommend fixes.

TOOL: msf_search
Use this to search Metasploit for exploit modules matching a service, version, or CVE.
TOOL_CALL: msf_search <service_or_cve> [version]
Example: TOOL_CALL: msf_search ssh OpenSSH 7.2
Example: TOOL_CALL: msf_search CVE-2017-0144
Example: TOOL_CALL: msf_search ms17_010
Run this when nmap finds a service version that may have known exploits.
Never run exploits automatically — always present options to the user first.

TOOL: msf_exploit
Use this to execute a Metasploit exploit module against a target.
NEVER run automatically. NEVER suggest without explicit user request.
The user will be shown exactly what will run and must type "yes" to confirm.
TOOL_CALL: msf_exploit <module_path> <target> <lhost> [lport] [payload]
Example: TOOL_CALL: msf_exploit exploit/windows/smb/ms17_010_eternalblue 192.168.1.5 192.168.1.100

TOOL: msf_sessions
Use this to list all active Metasploit meterpreter and shell sessions.
TOOL_CALL: msf_sessions
Run after an exploit to check whether a session was opened.

TOOL: msf_post
Use this to run a post-exploitation module on an active session.
NEVER run automatically — only on explicit user request.
TOOL_CALL: msf_post <session_id> <module_path>
Example: TOOL_CALL: msf_post 1 post/multi/recon/local_exploit_suggester
Example: TOOL_CALL: msf_post 1 post/multi/gather/env

TOOL: mitm_capture
Use this when you need to inspect live HTTP traffic to/from a target — useful for finding hidden endpoints, auth tokens, session cookies, or API calls.
NEVER run automatically — only when the user asks to intercept or inspect traffic.
To call it, respond with exactly this format on its own line:
TOOL_CALL: mitm_capture <target> [port]
Example: TOOL_CALL: mitm_capture http://192.168.1.1 8080
Example: TOOL_CALL: mitm_capture http://10.0.0.5
Default capture port is 8080. Inform the user they need to route traffic through the proxy.
After capture, highlight any auth headers, cookies, API keys, or sensitive parameters found.

TOOL: hydra_scan
Use this ONLY when the user explicitly asks to brute-force or test credentials.
NEVER suggest or auto-run hydra_scan — it must only execute on direct user request.
To call it, respond with exactly this format on its own line:
TOOL_CALL: hydra_scan <target> <service> <hydra_flags>
Example: TOOL_CALL: hydra_scan 192.168.1.1 ssh -l admin -P /usr/share/wordlists/rockyou.txt
Example: TOOL_CALL: hydra_scan 10.0.0.5 ftp -L users.txt -P passwords.txt
The user will be prompted to confirm before the command runs.
Never run hydra_scan automatically or without an explicit user request.

IMPORTANT: When user asks to scan anything, you MUST respond with a TOOL_CALL line.
Do not describe what you will do. Just output the TOOL_CALL line immediately.

After the tool runs, you will receive the output labeled TOOL_RESULT.
Analyze it and tell the user what you found in detail.

Rules:
- Always use TOOL_CALL format exactly as shown
- Never go outside defined scope in pentest mode
- Always think like a senior pentester"""


def _scope_check(target: str) -> str | None:
    """Returns an error string if target is out of scope, else None."""
    in_scope, reason = scope.is_in_scope(target)
    if not in_scope:
        msg = f"SCOPE VIOLATION: {reason}"
        console.print(f"\n[bold red]🚫 {msg}[/bold red]")
        if not scope.is_set():
            console.print("[dim yellow]Tip: define scope with: scope 192.168.1.0/24[/dim yellow]")
        return msg
    if scope.is_set():
        console.print(f"[dim green]✓ scope check passed: {target}[/dim green]")
    return None


def handle_tool_call(tool_line: str, available: dict) -> tuple:
    """Parse and execute a tool call from the agent. Returns (output, meta)."""
    try:
        parts = tool_line.replace("TOOL_CALL:", "").strip().split()

        if not parts:
            return "ERROR: empty tool call", {}

        tool_name = parts[0]

        # registry key is the base name without _scan/_capture suffix
        _registry_key = tool_name.replace("_scan", "").replace("_capture", "").replace("_search", "").replace("_exploit", "").replace("_sessions", "").replace("_post", "")
        _registry_map = {
            "nmap": "nmap", "gobuster": "gobuster", "sqlmap": "sqlmap",
            "nikto": "nikto", "hydra": "hydra", "zap": "zaproxy",
            "mitm": "mitmproxy", "msf": "metasploit",
        }
        _reg_name = _registry_map.get(_registry_key)
        if _reg_name and not available.get(_reg_name, True):
            from agent.core.tools_registry import REGISTRY
            tool = REGISTRY[_reg_name]
            fallback_note = " (manual fallback active)" if tool.fallback else f" Run: [yellow]{tool.apt}[/yellow]"
            if not tool.fallback:
                return f"{_reg_name} is not installed.{fallback_note}", {}
            console.print(f"[dim yellow]{_reg_name} not found — using manual fallback[/dim yellow]")

        if tool_name == "nmap_scan":
            if len(parts) < 2:
                return "ERROR: nmap_scan requires a target", {}

            target = parts[1]
            flags = " ".join(parts[2:]) if len(parts) > 2 else "-sV"

            err = _scope_check(target)
            if err:
                return err, {}

            result = nmap_scan(target, flags)
            output = nmap_format(result)

            if output is None:
                output = "Scan complete but no output returned."

            console.print(f"[dim]{output}[/dim]")
            return output, {"tool": "nmap_scan", "target": target, "scan_result": result}

        if tool_name == "gobuster_scan":
            if len(parts) < 2:
                return "ERROR: gobuster_scan requires a target", {}

            target = parts[1]
            flags = " ".join(parts[2:]) if len(parts) > 2 else ""

            err = _scope_check(target)
            if err:
                return err, {}

            result = gobuster_scan(target, flags)
            output = gobuster_format(result)

            if output is None:
                output = "Gobuster returned no output."

            console.print(f"[dim]{output}[/dim]")
            return output, {"tool": "gobuster_scan", "target": target}

        if tool_name == "sqlmap_scan":
            if len(parts) < 2:
                return "ERROR: sqlmap_scan requires a target URL", {}

            target = parts[1]
            flags = " ".join(parts[2:]) if len(parts) > 2 else ""

            err = _scope_check(target)
            if err:
                return err, {}

            result = sqlmap_scan(target, flags)
            output = sqlmap_format(result)

            if output is None:
                output = "SQLMap returned no output."

            console.print(f"[dim]{output}[/dim]")
            return output, {"tool": "sqlmap_scan", "target": target}

        if tool_name == "hydra_scan":
            if len(parts) < 3:
                return (
                    "ERROR: hydra_scan requires target and service "
                    "(e.g. hydra_scan 192.168.1.1 ssh -l admin -P /wordlist.txt)",
                    {},
                )

            target = parts[1]
            service = parts[2]
            flags = " ".join(parts[3:]) if len(parts) > 3 else ""

            err = _scope_check(target)
            if err:
                return err, {}

            hydra_cmd = f"hydra {flags} {service}://{target}".strip()
            console.print(f"\n[bold red]⚠  HYDRA — credential brute-force[/bold red]")
            console.print(f"[dim]command:[/dim] {hydra_cmd}")

            try:
                confirm = console.input("[bold yellow]Confirm execution? [y/N] → [/bold yellow]").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return "Hydra execution cancelled.", {}

            if confirm != "y":
                return "Hydra execution cancelled by user.", {}

            console.print(f"\n[bold yellow]⚡ executing:[/bold yellow] {hydra_cmd}")

            result = hydra_scan(target, service, flags)
            output = hydra_format(result)

            if output is None:
                output = "Hydra returned no output."

            console.print(f"[dim]{output}[/dim]")
            return output, {"tool": "hydra_scan", "target": target, "service": service}

        if tool_name == "nikto_scan":
            if len(parts) < 2:
                return "ERROR: nikto_scan requires a target", {}

            target = parts[1]
            flags = " ".join(parts[2:]) if len(parts) > 2 else ""

            err = _scope_check(target)
            if err:
                return err, {}

            result = nikto_scan(target, flags)
            output = nikto_format(result)

            if output is None:
                output = "Nikto returned no output."

            console.print(f"[dim]{output}[/dim]")
            return output, {"tool": "nikto_scan", "target": target}

        if tool_name == "zap_scan":
            if len(parts) < 2:
                return "ERROR: zap_scan requires a target", {}

            target = parts[1]

            err = _scope_check(target)
            if err:
                return err, {}

            result = zap_scan(target)
            output = zap_format(result)

            if output is None:
                output = "ZAP returned no output."

            console.print(f"[dim]{output}[/dim]")
            return output, {"tool": "zap_scan", "target": target}

        if tool_name == "mitm_capture":
            if len(parts) < 2:
                return "ERROR: mitm_capture requires a target", {}

            target = parts[1]
            port = int(parts[2]) if len(parts) > 2 else 8080

            err = _scope_check(target)
            if err:
                return err, {}

            console.print(f"\n[bold yellow]⚡ executing:[/bold yellow] mitmproxy capture → {target} (:{port})")
            console.print(
                f"[dim yellow]Route traffic through http://127.0.0.1:{port} to capture it.[/dim yellow]"
            )

            result = mitm_capture(target, port=port)
            output = mitm_format(result)

            if output is None:
                output = "mitmproxy returned no output."

            console.print(f"[dim]{output}[/dim]")
            return output, {"tool": "mitm_capture", "target": target}

        if tool_name == "msf_search":
            if len(parts) < 2:
                return "ERROR: msf_search requires a service, CVE, or keyword", {}

            query   = parts[1]
            version = " ".join(parts[2:]) if len(parts) > 2 else None

            is_cve = query.upper().startswith("CVE-") or query.upper().startswith("CVE")
            matches, msf_err = msf.search_exploit(
                cve=query if is_cve else None,
                service=None if is_cve else query,
                version=version,
            )
            output = msf.format_for_agent(matches) if not msf_err else f"MSF SEARCH ERROR: {msf_err}"
            console.print(f"[dim]{output}[/dim]")
            return output, {"tool": "msf_search", "target": query}

        if tool_name == "msf_exploit":
            if len(parts) < 4:
                return "ERROR: msf_exploit requires <module> <target> <lhost>", {}

            exploit_path = parts[1]
            target       = parts[2]
            lhost        = parts[3]
            extra        = parts[4:] if len(parts) > 4 else []

            options: dict = {}
            if extra:
                options["lport"] = extra[0]
            if len(extra) > 1:
                options["payload"] = extra[1]

            err = _scope_check(target)
            if err:
                return err, {}

            result = msf.run_exploit(
                exploit_path, target, lhost,
                options=options,
                scope_check=scope.is_in_scope,
            )
            output = msf.format_for_agent(result)
            console.print(f"[dim]{output}[/dim]")
            return output, {"tool": "msf_exploit", "target": target}

        if tool_name == "msf_sessions":
            sessions, msf_err = msf.get_sessions()
            output = msf.format_for_agent(sessions) if not msf_err else f"MSF SESSIONS ERROR: {msf_err}"
            console.print(f"[dim]{output}[/dim]")
            return output, {"tool": "msf_sessions", "target": "localhost"}

        if tool_name == "msf_post":
            if len(parts) < 3:
                return "ERROR: msf_post requires <session_id> <module>", {}

            session_id  = parts[1]
            post_module = parts[2]

            result = msf.run_post(session_id, post_module)
            output = msf.format_for_agent(result)
            console.print(f"[dim]{output}[/dim]")
            return output, {"tool": "msf_post", "target": session_id}

        return f"ERROR: unknown tool {tool_name}", {}

    except Exception as e:
        return f"ERROR: tool execution failed — {str(e)}", {}


def process_response(reply: str, history: list, router: ModelRouter, available: dict) -> str:
    """
    Check if agent wants to call a tool.
    If yes, run it and feed result back to agent (using smart model for analysis).
    If no, return reply as-is.
    """
    if not reply:
        return "No response from agent."

    lines = reply.split("\n")
    tool_lines = [l for l in lines if l.strip().startswith("TOOL_CALL:")]

    if not tool_lines:
        return reply

    tool_results = []
    tool_metas = []
    for tool_line in tool_lines:
        output, meta = handle_tool_call(tool_line, available)
        if output is None:
            output = "Tool returned no output."
        tool_results.append(output)
        tool_metas.append(meta)
        if meta.get("target") and output:
            ev_path = evidence.save_command_output(tool_line, output, meta["target"])
            console.print(f"[dim green]evidence saved → {ev_path}[/dim green]")

    tool_output = "\n\n".join(tool_results)

    planner_notes = []
    for meta in tool_metas:
        if meta.get("tool") == "nmap_scan":
            scan_result = meta.get("scan_result")
            actions = decide_next_tools(scan_result)

            for action in actions:
                if action.type == "auto_run" and action.tool == "gobuster_scan":
                    err = _scope_check(action.target)
                    if err:
                        tool_output += f"\n\n--- AUTO: gobuster on {action.target} BLOCKED ---\n{err}"
                        continue
                    console.print(
                        f"\n[bold cyan]⚡ planner:[/bold cyan] {action.reason} on {action.target}"
                    )
                    gb_result = gobuster_scan(action.target)
                    gb_output = gobuster_format(gb_result)
                    console.print(f"[dim]{gb_output}[/dim]")
                    tool_output += f"\n\n--- AUTO: gobuster on {action.target} ---\n{gb_output}"

                elif action.type == "auto_run" and action.tool == "nikto_scan":
                    err = _scope_check(action.target)
                    if err:
                        tool_output += f"\n\n--- AUTO: nikto on {action.target} BLOCKED ---\n{err}"
                        continue
                    console.print(
                        f"\n[bold cyan]⚡ planner:[/bold cyan] {action.reason} on {action.target}"
                    )
                    nk_result = nikto_scan(action.target, action.flags)
                    nk_output = nikto_format(nk_result)
                    console.print(f"[dim]{nk_output}[/dim]")
                    tool_output += f"\n\n--- AUTO: nikto on {action.target} ---\n{nk_output}"

                elif action.type == "auto_run" and action.tool == "zap_scan":
                    err = _scope_check(action.target)
                    if err:
                        tool_output += f"\n\n--- AUTO: zap on {action.target} BLOCKED ---\n{err}"
                        continue
                    console.print(
                        f"\n[bold cyan]⚡ planner:[/bold cyan] {action.reason} on {action.target}"
                    )
                    zp_result = zap_scan(action.target)
                    zp_output = zap_format(zp_result)
                    console.print(f"[dim]{zp_output}[/dim]")
                    tool_output += f"\n\n--- AUTO: zap on {action.target} ---\n{zp_output}"

                elif action.type == "suggest":
                    planner_notes.append(f"- {action.reason.replace('<target>', action.target)}")

    suggest_block = ""
    if planner_notes:
        suggest_block = "\n\nRECOMMENDED FOLLOW-UP:\n" + "\n".join(planner_notes)

    history.append({
        "role": "user",
        "content": f"TOOL_RESULT:\n{tool_output}{suggest_block}\n\nAnalyze these results and tell me what you found. Include any recommended follow-up steps."
    })

    with console.status("[dim]agent analyzing results...[/dim]", spinner="dots"):
        final_reply = router.legacy_chat("analyze", SYSTEM_PROMPT, history)
    history.append({
        "role": "assistant",
        "content": final_reply
    })

    for meta in tool_metas:
        if meta.get("tool") == "nmap_scan" and "scan_result" in meta:
            path = save_engagement(
                meta["target"], meta["scan_result"], final_reply,
                scope=scope.get_entries() or None,
            )
            console.print(f"\n[dim green]engagement saved → {path}[/dim green]")

    return final_reply


def _workflow_wizard() -> None:
    """
    Interactive first-run wizard to choose single vs multi-model workflow.
    Saves the choice to config.yaml.
    """
    console.print("\n" + "─" * 60)
    console.print("[bold cyan]ClawStrike — Workflow Setup[/bold cyan]\n")
    console.print("Choose your workflow:\n")
    console.print("  [bold white][1][/bold white] [bold]Single Model[/bold] — one AI handles everything")
    console.print("      (simpler, higher cost)\n")
    console.print("  [bold white][2][/bold white] [bold]Multi-Model[/bold] — different AI for different tasks")
    console.print("      (cost effective, recommended)")
    console.print("      [dim]→ Fast/free model: recon, scanning, enumeration[/dim]")
    console.print("      [dim]→ Smart model:     analysis, exploitation planning, reports[/dim]")
    console.print()

    while True:
        choice = console.input("[bold yellow]Enter choice [1/2] → [/bold yellow]").strip()
        if choice in ("1", "2"):
            break
        console.print("[dim red]Please enter 1 or 2.[/dim red]")

    if choice == "1":
        save_workflow_config("single", None, None)
        console.print("\n[bold green]✓ Single-model workflow saved.[/bold green]")
        return

    # ── Multi-model setup ──────────────────────────────────────────────────────
    console.print("\n[bold cyan]FAST MODEL[/bold cyan] [dim](recon, scanning, enumeration)[/dim]")
    console.print("[dim]Suggested: ollama (free), groq (free tier), deepseek (cheap), mistral free[/dim]\n")

    fast_provider = console.input("  Fast model provider [ollama/groq/deepseek/mistral/openai] → ").strip().lower() or "ollama"
    fast_model_name = console.input(f"  Fast model name [e.g. qwen2.5-coder:7b] → ").strip() or "qwen2.5-coder:7b"

    fast_api_key = ""
    fast_base_url = ""
    if fast_provider == "ollama":
        fast_base_url = console.input("  Ollama base URL [http://localhost:11434/v1] → ").strip() or "http://localhost:11434/v1"
        fast_api_key = "ollama"
    else:
        fast_api_key = console.input(f"  {fast_provider.capitalize()} API key → ").strip()

    fast = ModelConfig(
        provider=fast_provider,
        model=fast_model_name,
        api_key=fast_api_key,
        base_url=fast_base_url or None,
    )

    console.print("\n[bold cyan]SMART MODEL[/bold cyan] [dim](analysis, exploitation planning, reports)[/dim]")
    console.print("[dim]Suggested: Claude Opus/Sonnet, GPT-4o[/dim]\n")

    smart_provider = console.input("  Smart model provider [anthropic/openai/ollama] → ").strip().lower() or "anthropic"
    smart_model_name = console.input(f"  Smart model name [e.g. claude-opus-4-6] → ").strip() or "claude-opus-4-6"
    smart_api_key = console.input(f"  {smart_provider.capitalize()} API key (blank = use env var) → ").strip()
    smart_base_url = ""
    if smart_provider not in ("anthropic", "openai"):
        smart_base_url = console.input("  Base URL (leave blank for default) → ").strip()

    smart = ModelConfig(
        provider=smart_provider,
        model=smart_model_name,
        api_key=smart_api_key,
        base_url=smart_base_url or None,
    )

    save_workflow_config("multi", fast, smart)

    console.print(f"\n[bold green]✓ Multi-model workflow saved.[/bold green]")
    console.print(f"  [dim]fast  → {fast.provider}/{fast.model}[/dim]")
    console.print(f"  [dim]smart → {smart.provider}/{smart.model}[/dim]")
    console.print()

    # reload config so router picks up new settings
    global cfg
    from agent.core.config import load_config
    cfg = load_config()


def _handle_pentest(cmd: str, scope, router) -> None:
    """
    Handle:  pentest <target> [--profile stealth|standard|thorough|full]

    Shows engagement plan, requires y/n confirmation, then runs Methodology.
    """
    from agent.core.scan_profiles import get_profile, PROFILES

    parts = cmd.split()
    # parts[0] == "pentest", parts[1] == target, then optional --profile <name>
    if len(parts) < 2:
        console.print("[bold red]Usage:[/bold red] pentest <target> [--profile stealth|standard|thorough|full]")
        return

    target = parts[1]
    profile_name = "standard"

    if "--profile" in parts:
        idx = parts.index("--profile")
        if idx + 1 < len(parts):
            profile_name = parts[idx + 1].lower()

    profile = get_profile(profile_name)

    # Scope check
    in_scope, reason = scope.is_in_scope(target)
    if not in_scope:
        console.print(f"\n[bold red]🚫 SCOPE VIOLATION: {reason}[/bold red]")
        if not scope.is_set():
            console.print("[dim yellow]Tip: set scope first with: scope 192.168.1.0/24[/dim yellow]")
        return

    scope_display = scope.show() if scope.is_set() else "unrestricted (no scope set)"

    console.print(Panel(
        f"[bold]ClawStrike Engagement Plan[/bold]\n\n"
        f"  Target  : [cyan]{target}[/cyan]\n"
        f"  Profile : [yellow]{profile.name}[/yellow]  —  {profile.notes}\n"
        f"  Scope   : {scope_display}\n\n"
        f"  [dim]Phase 1[/dim]  Discovery        {profile.phase1_cmd.format(target=target)}\n"
        f"  [dim]Phase 2[/dim]  Service ID       {profile.phase2_cmd.format(ports='<discovered>', target=target)}\n"
        f"  [dim]Phase 3[/dim]  Targeted enum    per-service (gobuster/nikto/enum4linux/ssh-audit…)\n"
        f"  [dim]Phase 4[/dim]  CVE analysis     AI-assisted vulnerability matching\n"
        f"  [dim]Phase 5[/dim]  Exploit plan     Ranked options — [bold]human review required[/bold]\n"
        f"  [dim]Phase 6[/dim]  Report           Written to engagements/{target}/",
        title="Engagement Plan",
        border_style="yellow",
    ))

    try:
        confirm = console.input("\n[bold yellow]Proceed? [y/N] → [/bold yellow]").strip().lower()
    except (EOFError, KeyboardInterrupt):
        console.print("\n[dim]Engagement cancelled.[/dim]")
        return

    if confirm != "y":
        console.print("[dim]Engagement cancelled.[/dim]")
        return

    global current_session
    from agent.core.methodology import Methodology
    current_session = EngagementSession(
        target=target,
        profile=profile.name,
        scope=scope_display,
    )
    methodology = Methodology(target=target, profile=profile, router=router)
    result = methodology.run(current_session)

    if "error" in result:
        console.print(f"\n[bold red]Engagement stopped: {result['error']}[/bold red]")
        current_session = None
    else:
        post_exploiter.set_context(target)
        n = len(current_session.exploit_options)
        if n:
            console.print(
                f"\n[dim cyan]{n} exploit option(s) ready — "
                f"type 'exploit' to review.[/dim cyan]"
            )
        report = result.get("report")
        if report:
            console.print(f"\n[bold green]Engagement complete — report: {report}[/bold green]")
        else:
            console.print("\n[bold green]Engagement complete.[/bold green]")


def _check_for_updates():
    """Silently check if remote has new commits. Prints one line if behind."""
    try:
        subprocess.run(
            ["git", "fetch", "origin", "main"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        local = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
        ).strip()
        remote = subprocess.check_output(
            ["git", "rev-parse", "origin/main"],
            stderr=subprocess.DEVNULL,
        ).strip()
        if local != remote:
            console.print("[dim yellow]update available — run scripts/update.sh[/dim yellow]")
    except Exception:
        pass


def run():
    # ── First-run wizard: ask about workflow if not yet configured ─────────────
    if cfg.workflow == "single" and cfg.fast_model is None:
        import yaml
        from agent.core.config import CONFIG_PATH
        raw = {}
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH) as f:
                raw = yaml.safe_load(f) or {}
        if "workflow" not in raw:
            _workflow_wizard()

    # ── Re-build router after potential wizard changes ─────────────────────────
    router = NewModelRouter.from_config()

    # ── Tool availability check ────────────────────────────────────────────────
    available = check_tools(verbose=True)

    # ── Startup banner ─────────────────────────────────────────────────────────
    mode_line = f"\n[dim]{router.mode_label}[/dim]"

    console.print(Panel(
        f"[bold red]ClawStrike OS[/bold red] [dim]v{VERSION} — agent ready[/dim]"
        f"{mode_line}"
        f"  [dim]build: {BUILD_DATE}[/dim]\n\n"
        "[dim]commands: [/dim][bold]pentest <target> [--profile stealth|standard|thorough|full][/bold]\n"
        "[dim]           [/dim][bold]exploit[/bold][dim] · [/dim][bold]exploit <n>[/bold][dim] · [/dim]"
        "[bold]exploit all[/bold][dim] · [/dim][bold]skip <n>[/bold][dim] · [/dim][bold]manual <n>[/bold]\n"
        "[dim]           [/dim][bold]loot [session][/bold][dim] · [/dim][bold]pivot [session][/bold][dim] · [/dim]"
        "[bold]persist[/bold][dim] · [/dim][bold]persist <n> [session][/bold]\n"
        "[dim]           [/dim][bold]scope <cidr>[/bold][dim] · [/dim][bold]scope show[/bold][dim] · [/dim]"
        "[bold]scope clear[/bold][dim] · [/dim][bold]summary [target][/bold][dim] · [/dim]"
        "[bold]report <target>[/bold][dim] · [/dim][bold]tools[/bold][dim] · [/dim]"
        "[bold]tools install[/bold][dim] · [/dim][bold]exit[/bold]",
        border_style="red"
    ))

    threading.Thread(target=_check_for_updates, daemon=True).start()

    history = []

    while True:
        try:
            user_input = console.input("\n[bold red]claw@strike[/bold red] [dim]→[/dim] ")

            if user_input.strip().lower() in ("exit", "quit"):
                console.print("\n[dim]session ended.[/dim]")
                break

            if not user_input.strip():
                continue

            cmd = user_input.strip()

            if cmd.lower() == "scope show":
                console.print(f"\n[bold cyan]{scope.show()}[/bold cyan]")
                continue

            if cmd.lower() == "scope clear":
                scope.clear()
                console.print("\n[bold yellow]Scope cleared. All targets allowed.[/bold yellow]")
                continue

            if cmd.lower().startswith("scope "):
                entries = cmd[6:].strip().split()
                errors = scope.set_scope(*entries)
                if errors:
                    console.print(f"\n[bold red]Could not parse scope entries: {errors}[/bold red]")
                if scope.is_set():
                    console.print(f"\n[bold green]✓ Scope set:[/bold green] {scope.show()}")
                continue

            if cmd.lower() == "summary" or cmd.lower().startswith("summary "):
                summary_target = cmd[7:].strip() if cmd.lower().startswith("summary ") else None
                label = summary_target if summary_target else "all targets"

                engagements = load_engagements(summary_target)

                if not engagements:
                    console.print(f"\n[bold yellow]No engagement files found for {label}.[/bold yellow]")
                    continue

                console.print(f"\n[dim]loading {len(engagements)} engagement file(s) for {label}...[/dim]")

                combined = "\n\n---\n\n".join(
                    f"### File: {e['filename']}\n\n{e['content']}" for e in engagements
                )

                summary_prompt = (
                    f"You are reviewing engagement records for {label}. "
                    f"Based on the following engagement files, provide a structured session summary:\n\n"
                    f"1. **Targets scanned** — list each target and when it was scanned\n"
                    f"2. **Open ports & services** — consolidate across all scans\n"
                    f"3. **Key findings** — vulnerabilities, misconfigurations, notable results\n"
                    f"4. **Tools run** — which tools have been executed so far\n"
                    f"5. **Recommended next steps** — what hasn't been done yet and what to prioritize\n\n"
                    f"Engagement files:\n\n{combined}"
                )

                with console.status("[dim]generating summary...[/dim]", spinner="dots"):
                    summary = router.legacy_chat(
                        "report", SYSTEM_PROMPT,
                        [{"role": "user", "content": summary_prompt}]
                    )

                console.print(f"\n[bold blue]session summary →[/bold blue]")
                console.print(Markdown(summary))
                continue

            if cmd.lower() == "tools":
                available = check_tools(verbose=True)
                continue

            if cmd.lower() == "tools install":
                install_missing(available)
                available = check_tools(verbose=False)
                continue

            if cmd.lower().startswith("tools install "):
                tool_name_arg = cmd[14:].strip()
                install_tool(tool_name_arg)
                available = check_tools(verbose=False)
                continue

            if cmd.lower().startswith("exploit"):
                if not current_session:
                    console.print("[yellow]Run 'pentest <target>' first.[/yellow]")
                    continue
                if not current_session.exploit_options:
                    console.print("[yellow]No exploits found. Run pentest first.[/yellow]")
                    continue

                from agent.core.exploiter import execute_exploit
                parts_cmd = cmd.split()

                if len(parts_cmd) == 1 or (len(parts_cmd) > 1 and parts_cmd[1] == "all"):
                    for opt in current_session.exploit_options:
                        success = execute_exploit(opt, current_session)
                        if success:
                            post_exploiter.set_context(current_session.target)
                            break
                else:
                    try:
                        num = int(parts_cmd[1])
                        opt = current_session.get_exploit(num)
                        if opt:
                            success = execute_exploit(opt, current_session)
                            if success:
                                post_exploiter.set_context(current_session.target)
                        else:
                            console.print(f"[red]No exploit #{num}[/red]")
                    except ValueError:
                        console.print("[red]Usage: exploit <n>  or  exploit all[/red]")
                continue

            if cmd.lower().startswith("skip "):
                if not current_session:
                    console.print("[yellow]Run 'pentest <target>' first.[/yellow]")
                    continue
                try:
                    n = int(cmd.split()[1])
                    opt = current_session.get_exploit(n)
                    if opt:
                        opt.confidence = "skipped"
                        console.print(f"[dim]Option #{n} ({opt.title}) marked skipped.[/dim]")
                    else:
                        console.print(f"[red]No exploit #{n}[/red]")
                except (IndexError, ValueError):
                    console.print("[red]Usage: skip <n>[/red]")
                continue

            if cmd.lower().startswith("manual "):
                if not current_session:
                    console.print("[yellow]Run 'pentest <target>' first.[/yellow]")
                    continue
                try:
                    n = int(cmd.split()[1])
                    opt = current_session.get_exploit(n)
                    if opt:
                        from agent.core.exploiter import show_manual
                        show_manual(opt, current_session)
                    else:
                        console.print(f"[red]No exploit #{n}[/red]")
                except (IndexError, ValueError):
                    console.print("[red]Usage: manual <n>[/red]")
                continue

            if cmd.lower() == "loot" or cmd.lower().startswith("loot "):
                parts = cmd.split()
                try:
                    sid = int(parts[1]) if len(parts) > 1 else None
                except ValueError:
                    sid = None
                loot_output = post_exploiter.loot(sid)
                if loot_output and current_session is not None:
                    import datetime as _dt
                    current_session.loot.append(LootItem(
                        category="system_info",
                        label="Post-Exploitation Loot",
                        content=loot_output,
                        timestamp=_dt.datetime.now().isoformat(),
                        evidence_file="loot.txt",
                    ))
                continue

            if cmd.lower() == "pivot" or cmd.lower().startswith("pivot "):
                parts = cmd.split()
                try:
                    sid = int(parts[1]) if len(parts) > 1 else None
                except ValueError:
                    sid = None
                post_exploiter.pivot(sid)
                continue

            if cmd.lower() == "persist":
                post_exploiter.show_persist_options()
                continue

            if cmd.lower().startswith("persist "):
                parts = cmd.split()
                try:
                    n = int(parts[1])
                    sid = int(parts[2]) if len(parts) > 2 else None
                    post_exploiter.apply_persist(n, sid)
                except (IndexError, ValueError):
                    console.print("[red]Usage: persist <n> [session_id][/red]")
                continue

            if cmd.lower().startswith("pentest "):
                _handle_pentest(cmd, scope, router)
                continue

            if user_input.strip().lower().startswith("report "):
                target = user_input.strip()[7:].strip()
                default = Path.home() / "clawstrike_reports"
                default.mkdir(exist_ok=True)
                console.print(f"\n[bold]Where should the report be saved?[/bold]")
                console.print(f"[dim]Press Enter for default: {default}[/dim]")
                try:
                    user_path = console.input("[bold red]save to → [/bold red]").strip()
                except (EOFError, KeyboardInterrupt):
                    console.print("\n[dim]Cancelled.[/dim]")
                    continue
                if not user_path:
                    save_dir = default
                else:
                    save_dir = Path(user_path).expanduser().resolve()
                try:
                    save_dir.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    console.print(f"[red]Cannot create directory: {e}[/red]")
                    console.print("[dim]Using home directory instead[/dim]")
                    save_dir = Path.home()
                console.print(f"[dim]Generating report → {save_dir}[/dim]")
                with console.status(f"[dim]generating report for {target}...[/dim]", spinner="dots"):
                    result = generate_report(target, session=current_session, output_dir=save_dir)
                if result.startswith("ERROR"):
                    console.print(f"\n[bold red]{result}[/bold red]")
                else:
                    console.print(f"\n[bold green]✅ Report saved:[/bold green] {result}")
                continue

            history.append({
                "role": "user",
                "content": user_input
            })

            with console.status("[dim]agent thinking...[/dim]", spinner="dots"):
                reply = router.legacy_chat("plan", SYSTEM_PROMPT, history)

            if reply is None:
                console.print("[red]agent returned empty response[/red]")
                continue

            history.append({
                "role": "assistant",
                "content": reply
            })

            final = process_response(reply, history, router, available)

            console.print(f"\n[bold blue]agent →[/bold blue]")
            console.print(Markdown(final))

        except KeyboardInterrupt:
            console.print("\n[dim]interrupted.[/dim]")
            break
        except Exception as e:
            if "api" in type(e).__name__.lower() or "auth" in str(e).lower():
                console.print(f"\n[bold red]API error:[/bold red] {e}")
                break
            raise


if __name__ == "__main__":
    run()
