"""The ``report <target>`` command — generate a written engagement report."""

from __future__ import annotations

from pathlib import Path

from agent.core.context import CliContext
from agent.reports.generator import generate_report


def handle_report(ctx: CliContext, cmd: str) -> None:
    """Handle ``report <target>`` — prompt for a save location and generate."""
    console = ctx.console

    target = cmd[7:].strip()
    default = Path.home() / "clawstrike_reports"
    default.mkdir(exist_ok=True)
    console.print(f"\n[bold]Where should the report be saved?[/bold]")
    console.print(f"[dim]Press Enter for default: {default}[/dim]")
    try:
        user_path = console.input("[bold red]save to → [/bold red]").strip()
    except (EOFError, KeyboardInterrupt):
        console.print("\n[dim]Cancelled.[/dim]")
        return
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
        result = generate_report(target, session=ctx.session, output_dir=save_dir)
    if result.startswith("ERROR"):
        console.print(f"\n[bold red]{result}[/bold red]")
    else:
        console.print(f"\n[bold green]✅ Report saved:[/bold green] {result}")
