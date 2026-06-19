"""Tool-management commands: ``tools``, ``tools install``, ``tools install <name>``.

Refreshes ``ctx.available`` after any install so the dispatcher sees the new
availability map.
"""

from __future__ import annotations

from agent.core.context import CliContext
from agent.core.checker import check_tools, install_tool, install_missing


def handle_tools(ctx: CliContext, cmd: str) -> None:
    """Handle the ``tools`` family of commands."""
    lower = cmd.lower()

    if lower == "tools":
        ctx.available = check_tools(verbose=True)
        return

    if lower == "tools install":
        install_missing(ctx.available)
        ctx.available = check_tools(verbose=False)
        return

    if lower.startswith("tools install "):
        tool_name_arg = cmd[14:].strip()
        install_tool(tool_name_arg)
        ctx.available = check_tools(verbose=False)
