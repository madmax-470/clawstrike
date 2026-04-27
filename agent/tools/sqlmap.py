import subprocess
import re
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console

console = Console()


@dataclass
class SqlmapResult:
    target: str
    vulnerable_params: list = field(default_factory=list)
    databases: list = field(default_factory=list)
    raw_output: str = ""
    error: Optional[str] = None


def scan(target: str, flags: str = "") -> SqlmapResult:
    if not target.startswith("http://") and not target.startswith("https://"):
        target = f"http://{target}"

    command = [
        "sqlmap",
        "-u", target,
        "--batch",          # never prompt, use defaults
        "--output-dir=/tmp/sqlmap_clawstrike",
        "--level=1",
        "--risk=1",
    ]

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

        combined = stdout + stderr
        vulns, dbs = parse_output(combined)

        return SqlmapResult(
            target=target,
            vulnerable_params=vulns,
            databases=dbs,
            raw_output=combined,
        )

    except subprocess.TimeoutExpired:
        return SqlmapResult(
            target=target,
            error="sqlmap timed out after 180 seconds",
        )

    except FileNotFoundError:
        return SqlmapResult(
            target=target,
            error=(
                "sqlmap not found — install with:\n"
                "  sudo apt install sqlmap\n"
                "  pip install sqlmap\n\n"
                "Manual alternative (no tools needed):\n"
                "  Test boolean: curl '<url>?param=1 AND 1=1' vs '1 AND 1=2'\n"
                "  Test error:   curl '<url>?param=1\\''\n"
                "  Test time:    curl '<url>?param=1; SLEEP(5)--'"
            ),
        )

    except Exception as e:
        return SqlmapResult(target=target, error=str(e))


def parse_output(raw: str) -> tuple:
    """
    Extract vulnerable parameters and discovered databases from sqlmap output.
    Returns (vulnerable_params, databases).
    """
    vulnerable_params = []
    databases = []

    for line in raw.splitlines():
        line_s = line.strip()

        # injectable parameter lines: "Parameter: id (GET)"  or  "is vulnerable"
        if re.search(r"parameter[:\s]+'?\w+'?\s+\(", line_s, re.IGNORECASE):
            vulnerable_params.append(line_s)
        elif "is vulnerable" in line_s.lower():
            vulnerable_params.append(line_s)

        # database lines: "[*] information_schema"  or  "available databases [N]:"
        m = re.match(r"\[\*\]\s+(.+)", line_s)
        if m and "database" not in m.group(1).lower():
            # sqlmap lists db names prefixed with [*]
            databases.append(m.group(1).strip())

    return vulnerable_params, databases


def format_for_agent(result: SqlmapResult) -> str:
    if result.error:
        return f"SQLMAP ERROR: {result.error}"

    lines = [f"SQLMap scan complete on {result.target}.\n"]

    if result.vulnerable_params:
        lines.append(f"Vulnerable parameters ({len(result.vulnerable_params)}):")
        for v in result.vulnerable_params:
            lines.append(f"  {v}")
    else:
        lines.append("No injectable parameters detected.")

    if result.databases:
        lines.append(f"\nDiscovered databases ({len(result.databases)}):")
        for db in result.databases:
            lines.append(f"  {db}")

    return "\n".join(lines)
