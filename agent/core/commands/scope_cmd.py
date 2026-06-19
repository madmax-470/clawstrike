"""Scope commands: ``scope <cidr...>``, ``scope show``, ``scope clear``.

Thin command-handler layer over the ScopeManager engine in
``agent.core.scope`` (kept separate so the CLI wiring does not live in the
scope engine itself).
"""

from __future__ import annotations

from agent.core.context import CliContext


def handle_scope(ctx: CliContext, cmd: str) -> None:
    """Dispatch a ``scope ...`` command against ``ctx.scope``."""
    console = ctx.console
    scope = ctx.scope
    lower = cmd.lower()

    if lower == "scope show":
        console.print(f"\n[bold cyan]{scope.show()}[/bold cyan]")
        return

    if lower == "scope clear":
        scope.clear()
        console.print("\n[bold yellow]Scope cleared. All targets allowed.[/bold yellow]")
        return

    # "scope <entries...>"
    entries = cmd[6:].strip().split()
    errors = scope.set_scope(*entries)
    if errors:
        console.print(f"\n[bold red]Could not parse scope entries: {errors}[/bold red]")
    if scope.is_set():
        console.print(f"\n[bold green]✓ Scope set:[/bold green] {scope.show()}")
