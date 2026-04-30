from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from rich.console import Console
from agent.core.subprocess_utils import runner, tool_exists

console = Console()

_WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]


def _find_wordlist() -> Optional[str]:
    for wl in _WORDLISTS:
        if Path(wl).exists():
            return wl
    return None


@dataclass
class GobusterResult:
    target: str
    found_paths: list = field(default_factory=list)
    raw_output: str = ""
    error: Optional[str] = None


def scan(target: str, flags: str = "") -> GobusterResult:
    if not tool_exists("gobuster"):
        from agent.core.tools_registry import REGISTRY
        _t = REGISTRY["gobuster"]
        console.print(f"[dim yellow]gobuster not found — probing common paths manually. Install: {_t.apt}[/dim yellow]")
        if not target.startswith("http://") and not target.startswith("https://"):
            target = f"http://{target}"
        from agent.core import manual as _manual
        found = _manual.probe_common_paths(target)
        return GobusterResult(target=target, found_paths=found, raw_output="\n".join(found))

    if not target.startswith("http://") and not target.startswith("https://"):
        target = f"http://{target}"

    wordlist = _find_wordlist()
    if not wordlist:
        return GobusterResult(
            target=target,
            error=(
                "No wordlist found. Install one with:\n"
                "  apt install wordlists seclists dirb\n"
                "Searched:\n" + "\n".join(f"  {w}" for w in _WORDLISTS)
            ),
        )

    command = ["gobuster", "dir", "-u", target, "-w", wordlist, "-q"]
    if flags:
        command += flags.split()

    result = runner.run(command, label=f"gobuster → {target}", timeout=120)

    if result.tool_not_found:
        return GobusterResult(target=target, error="gobuster not found")

    if result.timed_out:
        return GobusterResult(
            target=target,
            raw_output=result.clean_output,
            error="gobuster timed out",
        )

    if result.returncode != 0 and not result.clean_output.strip():
        return GobusterResult(
            target=target,
            raw_output=result.clean_output,
            error=result.clean_output or f"gobuster exited with code {result.returncode}",
        )

    found = parse_output(result.clean_output)
    return GobusterResult(target=target, found_paths=found, raw_output=result.clean_output)


def parse_output(raw: str) -> list:
    paths = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("/") and "(Status:" in line:
            paths.append(line)
    return paths


def format_for_agent(result: GobusterResult) -> str:
    if result.error:
        return f"GOBUSTER ERROR: {result.error}"

    if not result.found_paths:
        return f"Gobuster scan complete on {result.target}. No paths found."

    lines = [f"Gobuster scan complete on {result.target}. Found {len(result.found_paths)} path(s):\n"]
    for path in result.found_paths:
        lines.append(f"  {path}")
    return "\n".join(lines)
