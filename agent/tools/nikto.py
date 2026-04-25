import subprocess
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console

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
    host = target
    for prefix in ("http://", "https://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
            break

    command = ["nikto", "-h", host]
    if flags:
        command += flags.split()

    console.print(f"[dim]running: {' '.join(command)}[/dim]")

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
        )

        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")

        if result.returncode != 0 and not stdout.strip():
            return NiktoResult(
                target=target,
                raw_output=stderr,
                error=stderr or f"nikto exited with code {result.returncode}",
            )

        findings = parse_output(stdout)
        return NiktoResult(target=target, findings=findings, raw_output=stdout)

    except subprocess.TimeoutExpired:
        return NiktoResult(
            target=target,
            error="nikto timed out after 180 seconds",
        )

    except FileNotFoundError:
        return NiktoResult(
            target=target,
            error=(
                "nikto not found — install with:\n"
                "  sudo apt install nikto           # Debian/Ubuntu\n"
                "  brew install nikto               # macOS"
            ),
        )

    except Exception as e:
        return NiktoResult(target=target, error=str(e))


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
