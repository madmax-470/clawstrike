import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console

console = Console()

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


@dataclass
class GobusterResult:
    target: str
    found_paths: list = field(default_factory=list)
    raw_output: str = ""
    error: Optional[str] = None


def scan(target: str, flags: str = "") -> GobusterResult:
    if not shutil.which("gobuster"):
        from agent.core.tools_registry import REGISTRY
        _t = REGISTRY["gobuster"]
        console.print(f"[dim yellow]gobuster not found — probing common paths manually. Install: {_t.apt}[/dim yellow]")
        if not target.startswith("http://") and not target.startswith("https://"):
            target = f"http://{target}"
        from agent.core import manual as _manual
        found = _manual.probe_common_paths(target)
        return GobusterResult(target=target, found_paths=found, raw_output="\n".join(found))

    # ensure target has a scheme
    if not target.startswith("http://") and not target.startswith("https://"):
        target = f"http://{target}"

    wordlist = DEFAULT_WORDLIST
    command = ["gobuster", "dir", "-u", target, "-w", wordlist, "-q"]

    if flags:
        command += flags.split()

    console.print(f"[dim]running: {' '.join(command)}[/dim]")

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )

        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")

        if result.returncode != 0 and not stdout.strip():
            return GobusterResult(
                target=target,
                raw_output=stderr,
                error=stderr or f"gobuster exited with code {result.returncode}",
            )

        found = parse_output(stdout)
        return GobusterResult(target=target, found_paths=found, raw_output=stdout)

    except subprocess.TimeoutExpired:
        return GobusterResult(
            target=target,
            error="gobuster timed out after 120 seconds",
        )

    except FileNotFoundError:
        from agent.core import manual as _manual
        console.print("[dim yellow]gobuster not found — probing common paths manually[/dim yellow]")
        found = _manual.probe_common_paths(target)
        return GobusterResult(
            target=target,
            found_paths=found,
            raw_output="\n".join(found),
        )

    except Exception as e:
        return GobusterResult(target=target, error=str(e))


def parse_output(raw: str) -> list:
    """Extract found paths from gobuster output lines like: /admin (Status: 200) [Size: 1234]"""
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
