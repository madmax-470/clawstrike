"""ClawStrike main entry point and REPL dispatcher.

After the Priority-1 refactor this module is intentionally thin: it owns the
interactive ``run()`` loop, ``process_response()`` (tool-result analysis), the
first-run workflow wizard, and the background update check. All individual
command handlers live under ``agent/core/commands/``; the text-based tool
dispatch lives in ``agent/core/tool_dispatcher.py``; the system prompt lives in
``agent/core/prompts.py``.

Shared state (session, scope, router, config, tool availability) is carried in
a single :class:`~agent.core.context.CliContext` threaded through every handler.
"""

import subprocess
import threading
from dotenv import load_dotenv
from version import VERSION, BUILD_DATE
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from agent.tools.gobuster import scan as gobuster_scan, format_for_agent as gobuster_format
from agent.tools.nikto import scan as nikto_scan, format_for_agent as nikto_format
from agent.tools.zap import start_scan as zap_scan, format_for_agent as zap_format
from agent.core import evidence
from agent.memory.store import save_engagement
from agent.core.planner import decide_next_tools
from agent.core.scope import ScopeManager
from agent.core.config import load_config, ModelConfig, save_workflow_config
from agent.core.checker import check_tools
from agent.core.model_router import ModelRouter
from agent.core.context import CliContext
from agent.core.prompts import SYSTEM_PROMPT
from agent.core.tool_definitions import TOOL_SCHEMAS
from agent.core.tool_dispatcher import dispatch_tool, parse_tool_line, _scope_check

from agent.core.commands.scope_cmd import handle_scope
from agent.core.commands.summary import handle_summary
from agent.core.commands.tools_cmd import handle_tools
from agent.core.commands.exploit import handle_exploit, handle_skip, handle_manual
from agent.core.commands.post_exploit import (
    handle_loot, handle_pivot, handle_persist, handle_wordlist,
)
from agent.core.commands.pentest import handle_pentest
from agent.core.commands.report import handle_report

load_dotenv()
console = Console()

cfg = load_config()


def _describe_call(name: str, args: dict) -> str:
    """Render a tool call as a short human/evidence-friendly string."""
    arg_str = " ".join(f"{k}={v}" for k, v in args.items())
    return f"{name} {arg_str}".strip()


def process_response(ctx: CliContext, reply: str) -> str:
    """Text-protocol fallback entry point.

    Scans ``reply`` for ``TOOL_CALL:`` lines (emitted by models without native
    function calling). If found, executes them through the shared
    :func:`_execute_and_analyze` core; otherwise returns ``reply`` unchanged.
    """
    if not reply:
        return "No response from agent."

    tool_lines = [l for l in reply.split("\n") if l.strip().startswith("TOOL_CALL:")]
    if not tool_lines:
        return reply

    calls = []
    for line in tool_lines:
        name, args = parse_tool_line(line)
        calls.append((name, args, line.strip()))

    return _execute_and_analyze(ctx, calls)


def _execute_and_analyze(ctx: CliContext, calls: list) -> str:
    """Execute tool calls, run planner follow-ups, and return the AI analysis.

    Shared by the native function-calling path (run()) and the text-protocol
    fallback (process_response()).

    ``calls`` is a list of ``(name, args, display)`` tuples, where ``display`` is
    a string used for evidence labelling.
    """
    console = ctx.console
    router = ctx.router
    scope = ctx.scope

    tool_results = []
    tool_metas = []
    for name, args, display in calls:
        output, meta = dispatch_tool(ctx, name, args)
        if output is None:
            output = "Tool returned no output."
        tool_results.append(output)
        tool_metas.append(meta)
        if meta.get("target") and output:
            ev_path = evidence.save_command_output(display, output, meta["target"])
            console.print(f"[dim green]evidence saved → {ev_path}[/dim green]")

    tool_output = "\n\n".join(tool_results)

    planner_notes = []
    for meta in tool_metas:
        if meta.get("tool") == "nmap_scan":
            scan_result = meta.get("scan_result")
            actions = decide_next_tools(scan_result)

            for action in actions:
                if action.type == "auto_run" and action.tool == "gobuster_scan":
                    err = _scope_check(ctx, action.target)
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
                    err = _scope_check(ctx, action.target)
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
                    err = _scope_check(ctx, action.target)
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

    ctx.history.append({
        "role": "user",
        "content": f"TOOL_RESULT:\n{tool_output}{suggest_block}\n\nAnalyze these results and tell me what you found. Include any recommended follow-up steps."
    })

    with console.status("[dim]agent analyzing results...[/dim]", spinner="dots"):
        final_reply = router.legacy_chat("analyze", SYSTEM_PROMPT, ctx.history)
    ctx.history.append({
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
    """Interactive first-run wizard to choose single vs multi-model workflow.

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
    cfg = load_config()


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


def _dispatch(ctx: CliContext, cmd: str) -> bool:
    """Route a single REPL command to its handler.

    Returns True if the command was handled here, False if it should fall
    through to the agent conversation path.
    """
    lower = cmd.lower()

    if lower in ("scope show", "scope clear") or lower.startswith("scope "):
        handle_scope(ctx, cmd)
        return True

    if lower == "summary" or lower.startswith("summary "):
        handle_summary(ctx, cmd)
        return True

    if lower == "tools" or lower == "tools install" or lower.startswith("tools install "):
        handle_tools(ctx, cmd)
        return True

    if lower.startswith("exploit"):
        handle_exploit(ctx, cmd)
        return True

    if lower.startswith("skip "):
        handle_skip(ctx, cmd)
        return True

    if lower.startswith("manual "):
        handle_manual(ctx, cmd)
        return True

    if lower == "loot" or lower.startswith("loot "):
        handle_loot(ctx, cmd)
        return True

    if lower.startswith("wordlist"):
        handle_wordlist(ctx, cmd)
        return True

    if lower == "pivot" or lower.startswith("pivot "):
        handle_pivot(ctx, cmd)
        return True

    if lower == "persist" or lower.startswith("persist "):
        handle_persist(ctx, cmd)
        return True

    if lower.startswith("pentest "):
        handle_pentest(ctx, cmd)
        return True

    if lower.startswith("report "):
        handle_report(ctx, cmd)
        return True

    return False


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
    router = ModelRouter.from_config()

    # ── Tool availability check ────────────────────────────────────────────────
    available = check_tools(verbose=True)

    # ── Shared session context ─────────────────────────────────────────────────
    ctx = CliContext(
        console=console,
        cfg=load_config(),
        scope=ScopeManager(),
        router=router,
        available=available,
    )

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

    while True:
        try:
            user_input = console.input("\n[bold red]claw@strike[/bold red] [dim]→[/dim] ")

            if user_input.strip().lower() in ("exit", "quit"):
                console.print("\n[dim]session ended.[/dim]")
                break

            if not user_input.strip():
                continue

            cmd = user_input.strip()

            if _dispatch(ctx, cmd):
                continue

            ctx.history.append({
                "role": "user",
                "content": user_input
            })

            # ── Native function calling first (Anthropic / OpenAI / compatible).
            #    Returns the assistant prose AND any structured tool calls in one
            #    round-trip. Models without native support fall through the JSON
            #    fallback in model_router and, failing that, the text TOOL_CALL
            #    protocol handled by process_response().
            with console.status("[dim]agent thinking...[/dim]", spinner="dots"):
                text, raw_calls = router.smart.call_with_tools_text(
                    ctx.history, TOOL_SCHEMAS, SYSTEM_PROMPT
                )

            if raw_calls:
                calls = [
                    (c["name"], c.get("input") or {},
                     _describe_call(c["name"], c.get("input") or {}))
                    for c in raw_calls
                ]
                # Synthetic assistant turn keeps user/assistant alternation valid
                # for the follow-up analysis call (Anthropic rejects two user
                # turns in a row).
                assistant_note = text or (
                    "Calling tools: " + ", ".join(d for *_, d in calls)
                )
                ctx.history.append({"role": "assistant", "content": assistant_note})
                final = _execute_and_analyze(ctx, calls)
            else:
                # No tool calls — use the prose we already have, or fall back to a
                # plain chat if the provider returned nothing usable.
                reply = text if text else router.legacy_chat(
                    "plan", SYSTEM_PROMPT, ctx.history
                )
                if not reply:
                    console.print("[red]agent returned empty response[/red]")
                    continue
                ctx.history.append({"role": "assistant", "content": reply})
                final = process_response(ctx, reply)

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
