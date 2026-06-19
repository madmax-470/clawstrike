"""The ``summary [target]`` command — AI-generated session summary.

Loads saved engagement records and asks the smart model to consolidate them
into a structured summary.
"""

from __future__ import annotations

from rich.markdown import Markdown

from agent.core.context import CliContext
from agent.core.prompts import SYSTEM_PROMPT
from agent.memory.store import load_engagements


def handle_summary(ctx: CliContext, cmd: str) -> None:
    """Handle ``summary`` / ``summary <target>``."""
    console = ctx.console
    router = ctx.router

    summary_target = cmd[7:].strip() if cmd.lower().startswith("summary ") else None
    label = summary_target if summary_target else "all targets"

    engagements = load_engagements(summary_target)

    if not engagements:
        console.print(f"\n[bold yellow]No engagement files found for {label}.[/bold yellow]")
        return

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
