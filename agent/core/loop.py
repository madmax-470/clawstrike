from dotenv import load_dotenv
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from agent.tools.nmap import scan as nmap_scan, format_for_agent as nmap_format
from agent.tools.gobuster import scan as gobuster_scan, format_for_agent as gobuster_format
from agent.tools.sqlmap import scan as sqlmap_scan, format_for_agent as sqlmap_format
from agent.tools.nikto import scan as nikto_scan, format_for_agent as nikto_format
from agent.tools.hydra import scan as hydra_scan, format_for_agent as hydra_format
from agent.memory.store import save_engagement, load_engagements
from agent.core.planner import decide_next_tools
from agent.core.scope import ScopeManager
from agent.reports.generator import generate_report
from agent.core.config import load_config, build_client, chat

load_dotenv()
console = Console()

cfg    = load_config()
client = build_client(cfg)
scope  = ScopeManager()

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


def handle_tool_call(tool_line: str) -> tuple:
    """Parse and execute a tool call from the agent. Returns (output, meta)."""
    try:
        parts = tool_line.replace("TOOL_CALL:", "").strip().split()

        if not parts:
            return "ERROR: empty tool call", {}

        tool_name = parts[0]

        if tool_name == "nmap_scan":
            if len(parts) < 2:
                return "ERROR: nmap_scan requires a target", {}

            target = parts[1]
            flags = " ".join(parts[2:]) if len(parts) > 2 else "-sV"

            err = _scope_check(target)
            if err:
                return err, {}

            console.print(f"\n[bold yellow]⚡ executing:[/bold yellow] nmap {flags} {target}")

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

            console.print(f"\n[bold yellow]⚡ executing:[/bold yellow] gobuster dir -u {target}")

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

            console.print(f"\n[bold yellow]⚡ executing:[/bold yellow] sqlmap -u {target} --batch")

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

            console.print(f"\n[bold yellow]⚡ executing:[/bold yellow] nikto -h {target} {flags}".strip())

            result = nikto_scan(target, flags)
            output = nikto_format(result)

            if output is None:
                output = "Nikto returned no output."

            console.print(f"[dim]{output}[/dim]")
            return output, {"tool": "nikto_scan", "target": target}

        return f"ERROR: unknown tool {tool_name}", {}

    except Exception as e:
        return f"ERROR: tool execution failed — {str(e)}", {}


def process_response(reply: str, history: list) -> str:
    """
    Check if agent wants to call a tool.
    If yes, run it and feed result back to agent.
    If no, return reply as-is.
    """
    if not reply:
        return "No response from agent."

    lines = reply.split("\n")
    tool_lines = [l for l in lines if l.strip().startswith("TOOL_CALL:")]

    if not tool_lines:
        return reply

    # execute each tool call
    tool_results = []
    tool_metas = []
    for tool_line in tool_lines:
        output, meta = handle_tool_call(tool_line)
        if output is None:
            output = "Tool returned no output."
        tool_results.append(output)
        tool_metas.append(meta)

    # feed results back to agent
    tool_output = "\n\n".join(tool_results)

    # run planner on nmap results — auto-execute or suggest follow-up tools
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
        final_reply = chat(client, cfg, SYSTEM_PROMPT, history)
    history.append({
        "role": "assistant",
        "content": final_reply
    })

    # save engagement for every nmap scan
    for meta in tool_metas:
        if meta.get("tool") == "nmap_scan" and "scan_result" in meta:
            path = save_engagement(
                meta["target"], meta["scan_result"], final_reply,
                scope=scope.get_entries() or None,
            )
            console.print(f"\n[dim green]engagement saved → {path}[/dim green]")

    return final_reply


def run():
    console.print(Panel(
        "[bold red]ClawStrike OS[/bold red] [dim]v0.1 — agent ready[/dim]\n"
        f"[dim]provider: {cfg.provider}  |  model: {cfg.model}[/dim]\n\n"
        "[dim]commands: [/dim][bold]scope <cidr>[/bold][dim] · [/dim][bold]scope show[/bold][dim] · [/dim]"
        "[bold]scope clear[/bold][dim] · [/dim][bold]summary [target][/bold][dim] · [/dim]"
        "[bold]report <target>[/bold][dim] · [/dim][bold]exit[/bold]",
        border_style="red"
    ))

    history = []

    while True:
        try:
            user_input = console.input("\n[bold red]claw@strike[/bold red] [dim]→[/dim] ")

            if user_input.strip().lower() in ("exit", "quit"):
                console.print("\n[dim]session ended.[/dim]")
                break

            if not user_input.strip():
                continue

            # built-in command: scope
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

            # built-in command: summary [target]
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
                    summary = chat(
                        client, cfg, SYSTEM_PROMPT,
                        [{"role": "user", "content": summary_prompt}]
                    )

                console.print(f"\n[bold blue]session summary →[/bold blue]")
                console.print(Markdown(summary))
                continue

            # built-in command: report <target>
            if user_input.strip().lower().startswith("report "):
                target = user_input.strip()[7:].strip()
                with console.status(f"[dim]generating report for {target}...[/dim]", spinner="dots"):
                    result = generate_report(target)
                if result.startswith("ERROR"):
                    console.print(f"\n[bold red]{result}[/bold red]")
                else:
                    console.print(f"\n[bold green]report saved →[/bold green] {result}")
                continue

            history.append({
                "role": "user",
                "content": user_input
            })

            with console.status("[dim]agent thinking...[/dim]", spinner="dots"):
                reply = chat(client, cfg, SYSTEM_PROMPT, history)

            if reply is None:
                console.print("[red]agent returned empty response[/red]")
                continue

            history.append({
                "role": "assistant",
                "content": reply
            })

            final = process_response(reply, history)

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