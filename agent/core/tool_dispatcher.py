"""Tool-call dispatch for ClawStrike.

Executes ClawStrike tools from either of two sources, sharing one execution body
(:func:`dispatch_tool`):

* **Native function calling** — structured ``{"name", "input"}`` calls produced
  by ``router.smart.call_with_tools_text()`` (Anthropic / OpenAI / compatible).
* **Text protocol fallback** — legacy ``TOOL_CALL: <tool> <args>`` lines emitted
  by models without native tool support. :func:`parse_tool_line` turns one such
  line into ``(name, args)`` which is then handed to :func:`dispatch_tool`.

Both ``dispatch_tool`` and the scope check take a :class:`CliContext` so they can
reach the shared scope manager, console, and tool-availability map without
relying on module-level globals.
"""

from __future__ import annotations

from typing import Optional

from agent.tools.nmap import scan as nmap_scan, format_for_agent as nmap_format
from agent.tools.gobuster import scan as gobuster_scan, format_for_agent as gobuster_format
from agent.tools.sqlmap import scan as sqlmap_scan, format_for_agent as sqlmap_format
from agent.tools.nikto import scan as nikto_scan, format_for_agent as nikto_format
from agent.tools.hydra import scan as hydra_scan, format_for_agent as hydra_format
from agent.tools.zap import start_scan as zap_scan, format_for_agent as zap_format
from agent.tools.mitm import capture_traffic as mitm_capture, format_for_agent as mitm_format
from agent.tools import metasploit as msf

from agent.core.context import CliContext


# Maps a tool name to its tools_registry key (used for the install check).
_REGISTRY_MAP = {
    "nmap": "nmap", "gobuster": "gobuster", "sqlmap": "sqlmap",
    "nikto": "nikto", "hydra": "hydra", "zap": "zaproxy",
    "mitm": "mitmproxy", "msf": "metasploit",
}


def _scope_check(ctx: CliContext, target: str) -> Optional[str]:
    """Return an error string if ``target`` is out of scope, else None."""
    in_scope, reason = ctx.scope.is_in_scope(target)
    if not in_scope:
        msg = f"SCOPE VIOLATION: {reason}"
        ctx.console.print(f"\n[bold red]🚫 {msg}[/bold red]")
        if not ctx.scope.is_set():
            ctx.console.print("[dim yellow]Tip: define scope with: scope 192.168.1.0/24[/dim yellow]")
        return msg
    if ctx.scope.is_set():
        ctx.console.print(f"[dim green]✓ scope check passed: {target}[/dim green]")
    return None


def _tool_install_check(ctx: CliContext, tool_name: str) -> Optional[str]:
    """Check whether the underlying CLI tool is installed.

    Returns an error string to abort with if the tool is missing and has no
    manual fallback; otherwise returns None (printing a note when a fallback is
    being used).
    """
    registry_key = (
        tool_name.replace("_scan", "").replace("_capture", "").replace("_search", "")
        .replace("_exploit", "").replace("_sessions", "").replace("_post", "")
    )
    reg_name = _REGISTRY_MAP.get(registry_key)
    if reg_name and not ctx.available.get(reg_name, True):
        from agent.core.tools_registry import REGISTRY
        tool = REGISTRY[reg_name]
        if not tool.fallback:
            return f"{reg_name} is not installed. Run: [yellow]{tool.apt}[/yellow]"
        ctx.console.print(f"[dim yellow]{reg_name} not found — using manual fallback[/dim yellow]")
    return None


def parse_tool_line(tool_line: str) -> tuple[str, dict]:
    """Parse a text ``TOOL_CALL:`` line into ``(tool_name, args)``.

    Positional tokens are mapped to the same canonical argument keys used by the
    native tool schemas. Missing/optional tokens are simply omitted — presence
    validation happens in :func:`dispatch_tool`.
    """
    parts = tool_line.replace("TOOL_CALL:", "").strip().split()
    if not parts:
        return "", {}

    name = parts[0]
    rest = parts[1:]

    def _at(i: int) -> Optional[str]:
        return rest[i] if i < len(rest) else None

    args: dict = {}

    if name in ("nmap_scan", "gobuster_scan", "nikto_scan"):
        if _at(0) is not None:
            args["target"] = rest[0]
        if len(rest) > 1:
            args["flags"] = " ".join(rest[1:])

    elif name == "sqlmap_scan":
        if _at(0) is not None:
            args["url"] = rest[0]
        if len(rest) > 1:
            args["flags"] = " ".join(rest[1:])

    elif name == "zap_scan":
        if _at(0) is not None:
            args["target"] = rest[0]

    elif name == "hydra_scan":
        if _at(0) is not None:
            args["target"] = rest[0]
        if _at(1) is not None:
            args["service"] = rest[1]
        if len(rest) > 2:
            args["flags"] = " ".join(rest[2:])

    elif name == "mitm_capture":
        if _at(0) is not None:
            args["target"] = rest[0]
        if _at(1) is not None:
            args["port"] = rest[1]

    elif name == "msf_search":
        if _at(0) is not None:
            args["query"] = rest[0]
        if len(rest) > 1:
            args["version"] = " ".join(rest[1:])

    elif name == "msf_exploit":
        for key, idx in (("module", 0), ("target", 1), ("lhost", 2),
                         ("lport", 3), ("payload", 4)):
            if _at(idx) is not None:
                args[key] = rest[idx]

    elif name == "msf_post":
        if _at(0) is not None:
            args["session_id"] = rest[0]
        if _at(1) is not None:
            args["module"] = rest[1]

    # msf_sessions takes no arguments.
    return name, args


def dispatch_tool(ctx: CliContext, tool_name: str, args: dict) -> tuple:
    """Execute a single tool call. Returns ``(output, meta)``.

    ``args`` uses the canonical keys defined in
    :data:`agent.core.tool_definitions.TOOL_SCHEMAS`. Shared by the native and
    text-protocol paths. Never raises — failures are returned as an error string.
    """
    console = ctx.console
    try:
        if not tool_name:
            return "ERROR: empty tool call", {}

        install_err = _tool_install_check(ctx, tool_name)
        if install_err:
            return install_err, {}

        if tool_name == "nmap_scan":
            target = args.get("target")
            if not target:
                return "ERROR: nmap_scan requires a target", {}
            flags = args.get("flags") or "-sV"

            err = _scope_check(ctx, target)
            if err:
                return err, {}

            result = nmap_scan(target, flags)
            output = nmap_format(result) or "Scan complete but no output returned."
            console.print(f"[dim]{output}[/dim]")
            return output, {"tool": "nmap_scan", "target": target, "scan_result": result}

        if tool_name == "gobuster_scan":
            target = args.get("target")
            if not target:
                return "ERROR: gobuster_scan requires a target", {}
            flags = args.get("flags") or ""

            err = _scope_check(ctx, target)
            if err:
                return err, {}

            result = gobuster_scan(target, flags)
            output = gobuster_format(result) or "Gobuster returned no output."
            console.print(f"[dim]{output}[/dim]")
            return output, {"tool": "gobuster_scan", "target": target}

        if tool_name == "sqlmap_scan":
            target = args.get("url") or args.get("target")
            if not target:
                return "ERROR: sqlmap_scan requires a target URL", {}
            flags = args.get("flags") or ""

            err = _scope_check(ctx, target)
            if err:
                return err, {}

            result = sqlmap_scan(target, flags)
            output = sqlmap_format(result) or "SQLMap returned no output."
            console.print(f"[dim]{output}[/dim]")
            return output, {"tool": "sqlmap_scan", "target": target}

        if tool_name == "hydra_scan":
            target = args.get("target")
            service = args.get("service")
            if not target or not service:
                return (
                    "ERROR: hydra_scan requires target and service "
                    "(e.g. hydra_scan 192.168.1.1 ssh -l admin -P /wordlist.txt)",
                    {},
                )
            flags = args.get("flags") or ""

            err = _scope_check(ctx, target)
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
            output = hydra_format(result) or "Hydra returned no output."
            console.print(f"[dim]{output}[/dim]")
            return output, {"tool": "hydra_scan", "target": target, "service": service}

        if tool_name == "nikto_scan":
            target = args.get("target")
            if not target:
                return "ERROR: nikto_scan requires a target", {}
            flags = args.get("flags") or ""

            err = _scope_check(ctx, target)
            if err:
                return err, {}

            result = nikto_scan(target, flags)
            output = nikto_format(result) or "Nikto returned no output."
            console.print(f"[dim]{output}[/dim]")
            return output, {"tool": "nikto_scan", "target": target}

        if tool_name == "zap_scan":
            target = args.get("target")
            if not target:
                return "ERROR: zap_scan requires a target", {}

            err = _scope_check(ctx, target)
            if err:
                return err, {}

            result = zap_scan(target)
            output = zap_format(result) or "ZAP returned no output."
            console.print(f"[dim]{output}[/dim]")
            return output, {"tool": "zap_scan", "target": target}

        if tool_name == "mitm_capture":
            target = args.get("target")
            if not target:
                return "ERROR: mitm_capture requires a target", {}
            try:
                port = int(args.get("port") or 8080)
            except (TypeError, ValueError):
                port = 8080

            err = _scope_check(ctx, target)
            if err:
                return err, {}

            console.print(f"\n[bold yellow]⚡ executing:[/bold yellow] mitmproxy capture → {target} (:{port})")
            console.print(
                f"[dim yellow]Route traffic through http://127.0.0.1:{port} to capture it.[/dim yellow]"
            )

            result = mitm_capture(target, port=port)
            output = mitm_format(result) or "mitmproxy returned no output."
            console.print(f"[dim]{output}[/dim]")
            return output, {"tool": "mitm_capture", "target": target}

        if tool_name == "msf_search":
            query = args.get("query") or args.get("target")
            if not query:
                return "ERROR: msf_search requires a service, CVE, or keyword", {}
            version = args.get("version")

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
            module = args.get("module")
            target = args.get("target")
            lhost = args.get("lhost")
            if not module or not target or not lhost:
                return "ERROR: msf_exploit requires <module> <target> <lhost>", {}

            options: dict = {}
            if args.get("lport"):
                options["lport"] = args["lport"]
            if args.get("payload"):
                options["payload"] = args["payload"]

            err = _scope_check(ctx, target)
            if err:
                return err, {}

            result = msf.run_exploit(
                module, target, lhost,
                options=options,
                scope_check=ctx.scope.is_in_scope,
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
            session_id = args.get("session_id")
            post_module = args.get("module")
            if not session_id or not post_module:
                return "ERROR: msf_post requires <session_id> <module>", {}

            result = msf.run_post(session_id, post_module)
            output = msf.format_for_agent(result)
            console.print(f"[dim]{output}[/dim]")
            return output, {"tool": "msf_post", "target": session_id}

        return f"ERROR: unknown tool {tool_name}", {}

    except Exception as e:
        return f"ERROR: tool execution failed — {str(e)}", {}


def handle_tool_call(ctx: CliContext, tool_line: str) -> tuple:
    """Parse and execute a text ``TOOL_CALL:`` line. Returns ``(output, meta)``.

    Thin wrapper kept for the text-protocol fallback path: parse then dispatch.
    """
    name, args = parse_tool_line(tool_line)
    return dispatch_tool(ctx, name, args)
