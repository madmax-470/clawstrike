from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console
from agent.core.subprocess_utils import run_tool, tool_exists

console = Console()

_SKIP_PREFIXES = (
    "+ Target IP:",
    "+ Target Hostname:",
    "+ Target Port:",
    "+ Start Time:",
    "+ End Time:",
    "+ 1 host(s) tested",
    "+ requests made",
)


@dataclass
class NiktoFinding:
    description: str


@dataclass
class NiktoResult:
    target: str
    findings: list = field(default_factory=list)
    raw_output: str = ""
    error: Optional[str] = None


def scan(target: str, flags: str = "") -> NiktoResult:
    if not tool_exists("nikto"):
        from agent.core.tools_registry import REGISTRY
        _t = REGISTRY["nikto"]
        console.print(f"[dim yellow]nikto not found — running manual HTTP fingerprint. Install: {_t.apt}[/dim yellow]")
        from agent.core import manual as _manual
        r = _manual.http_fingerprint(target)
        summary = _manual.format_http_fingerprint(r)
        findings = [
            NiktoFinding(description=line.strip())
            for line in summary.splitlines()
            if line.strip() and not line.startswith("Manual HTTP")
        ]
        return NiktoResult(target=target, findings=findings, raw_output=summary)

    host = target
    for prefix in ("http://", "https://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
            break

    # -maxtime caps nikto's own internal timer; -nointeractive prevents prompts
    command = ["nikto", "-h", host, "-maxtime", "120", "-nointeractive"]
    if flags:
        command += flags.split()

    console.print(f"[dim]running: {' '.join(command)}[/dim]")

    # subprocess timeout is 150s — 30s grace over nikto's own -maxtime 120
    stdout, stderr, returncode = run_tool(command, timeout=150)

    if returncode != 0 and not stdout.strip():
        return NiktoResult(
            target=target,
            raw_output=stderr,
            error=stderr or f"nikto exited with code {returncode}",
        )

    findings = parse_output(stdout)
    return NiktoResult(target=target, findings=findings, raw_output=stdout)


def parse_output(raw: str) -> list:
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("+ "):
            continue
        if any(line.startswith(skip) for skip in _SKIP_PREFIXES):
            continue
        findings.append(NiktoFinding(description=line[2:]))
    return findings


def format_for_agent(result: NiktoResult) -> str:
    if result.error:
        return f"NIKTO ERROR: {result.error}"

    if not result.findings:
        return f"Nikto scan complete on {result.target}. No findings."

    lines = [f"Nikto scan complete on {result.target}. Found {len(result.findings)} finding(s):\n"]
    for f in result.findings:
        lines.append(f"  + {f.description}")
    return "\n".join(lines)
