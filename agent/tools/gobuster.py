import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from rich.console import Console

from agent.core.subprocess_utils import runner, tool_exists

console = Console()

WORDLIST_PATHS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/wordlists/dirb/small.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/big.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]


def find_wordlist() -> Optional[str]:
    for path in WORDLIST_PATHS:
        if Path(path).exists():
            return path
    return None


def classify_status(code: int) -> str:
    mapping = {
        200: "accessible",
        204: "no content",
        301: "redirect",
        302: "redirect",
        307: "redirect",
        401: "auth required",
        403: "forbidden",
        405: "method not allowed",
        500: "server error",
    }
    return mapping.get(code, f"status {code}")


@dataclass
class GobusterResult:
    target: str
    found_paths: list = field(default_factory=list)         # ["/admin", "/login"]
    paths_with_codes: dict = field(default_factory=dict)    # {"/admin": 403}
    raw_output: str = ""
    error: Optional[str] = None


def scan(target: str, flags: str = "") -> GobusterResult:
    if not tool_exists("gobuster"):
        console.print("[dim yellow]gobuster not found — use webscanner fallback[/dim yellow]")
        return GobusterResult(target=target, error="gobuster not installed")

    if not target.startswith("http://") and not target.startswith("https://"):
        target = f"http://{target}"

    wordlist = find_wordlist()
    if not wordlist:
        console.print(
            "[red]No wordlist found.[/red]\n"
            "Install with: apt install dirb seclists wordlists"
        )
        return GobusterResult(target=target, error="no wordlist available")

    command = [
        "gobuster", "dir",
        "-u", target,
        "-w", wordlist,
        "-q",
        "--status-codes", "200,204,301,302,307,401,403,405",
        "--no-error",
        "-t", "20",
    ]
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

    paths, codes = parse_output(result.clean_output)
    return GobusterResult(
        target=target,
        found_paths=paths,
        paths_with_codes=codes,
        raw_output=result.clean_output,
    )


def parse_output(raw: str) -> tuple:
    """Return ([paths], {path: code}) from gobuster -q output."""
    paths = []
    codes = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("/"):
            continue
        m = re.search(r"\(Status:\s*(\d+)\)", line)
        if not m:
            continue
        code = int(m.group(1))
        # strip everything after the path (gobuster outputs: /path (Status: NNN) [Size: NNN])
        path = line.split()[0]
        paths.append(path)
        codes[path] = code
    return paths, codes


def format_for_agent(result: GobusterResult) -> str:
    if result.error:
        return f"GOBUSTER ERROR: {result.error}"

    if not result.found_paths:
        return f"Gobuster scan complete on {result.target}. No paths found."

    lines = [f"Found {len(result.found_paths)} web path(s) on {result.target}:\n"]
    for path in result.found_paths:
        code = result.paths_with_codes.get(path, 0)
        label = classify_status(code)
        interesting = "  ⚠ INTERESTING" if code in (200, 401, 403) else ""
        lines.append(f"  {path:<35} [{code} {label}]{interesting}")
    return "\n".join(lines)
