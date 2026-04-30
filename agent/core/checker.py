import shutil
import subprocess
from rich.console import Console
from rich.table import Table
from rich import box
from agent.core.tools_registry import REGISTRY

console = Console()


def check_tools(verbose: bool = True) -> dict[str, bool]:
    """
    Run shutil.which() against every tool in REGISTRY.
    Returns {tool_name: is_available}.
    Prints a status table if verbose=True.
    Warns loudly for missing critical tools.
    """
    available: dict[str, bool] = {}

    for name, tool in REGISTRY.items():
        available[name] = shutil.which(tool.binary) is not None

    if verbose:
        _print_table(available)

    for name, ok in available.items():
        if ok:
            continue
        tool = REGISTRY[name]
        if tool.critical:
            console.print(
                f"[bold red]⚠  CRITICAL:[/bold red] [bold]{name}[/bold] not installed — "
                f"run: [yellow]{tool.apt}[/yellow]"
            )
        else:
            fallback_note = "  [dim](manual fallback active)[/dim]" if tool.fallback else ""
            console.print(
                f"[yellow]  ✗  {name}[/yellow] not installed — "
                f"run: [dim]{tool.apt}[/dim]{fallback_note}"
            )

    return available


def _print_table(available: dict[str, bool]) -> None:
    table = Table(
        title="ClawStrike — Tool Status",
        box=box.SIMPLE_HEAD,
        show_lines=False,
        title_style="bold red",
    )
    table.add_column("Tool",     style="bold white", no_wrap=True)
    table.add_column("Status",   no_wrap=True)
    table.add_column("Type",     style="dim", no_wrap=True)
    table.add_column("Fallback", style="dim", no_wrap=True)

    for name, ok in available.items():
        tool = REGISTRY[name]
        status   = "[bold green]✓ installed[/bold green]" if ok else "[bold red]✗ not found[/bold red]"
        kind     = "[red]critical[/red]" if tool.critical else "optional"
        fallback = "yes" if tool.fallback else "—"
        table.add_row(name, status, kind, fallback)

    console.print()
    console.print(table)


def install_tool(name: str) -> bool:
    """
    Run the apt install command for a single tool.
    Returns True if successful.
    """
    if name not in REGISTRY:
        console.print(f"[bold red]Unknown tool:[/bold red] {name}")
        return False

    tool = REGISTRY[name]
    console.print(f"\n[bold yellow]installing:[/bold yellow] {tool.apt}")

    result = subprocess.run(tool.apt.split(), capture_output=False)
    if result.returncode == 0:
        console.print(f"[bold green]✓ {name} installed.[/bold green]")
        if tool.pip:
            console.print(f"[dim]also installing pip package: {tool.pip}[/dim]")
            subprocess.run(["pip", "install", tool.pip], capture_output=False)
        return True
    else:
        console.print(f"[bold red]✗ install failed for {name}[/bold red]")
        return False


def install_missing(available: dict[str, bool]) -> None:
    """
    Show install commands for all missing tools, confirm, then install approved ones.
    """
    missing = {n: REGISTRY[n] for n, ok in available.items() if not ok}

    if not missing:
        console.print("\n[bold green]All tools are installed.[/bold green]")
        return

    console.print("\n[bold yellow]Missing tools:[/bold yellow]\n")
    for name, tool in missing.items():
        kind = "[red]critical[/red]" if tool.critical else "optional"
        console.print(f"  [{kind}] [bold]{name}[/bold]  →  {tool.apt}")

    console.print()
    try:
        confirm = console.input(
            "[bold yellow]Install all missing tools? [y/N] → [/bold yellow]"
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return

    if confirm != "y":
        console.print("[dim]Install cancelled.[/dim]")
        return

    for name in missing:
        install_tool(name)
