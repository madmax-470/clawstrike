import re
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console
from agent.core.subprocess_utils import runner, tool_exists

console = Console()


@dataclass
class SqlmapResult:
    target: str
    vulnerable_params: list = field(default_factory=list)
    databases: list = field(default_factory=list)
    raw_output: str = ""
    error: Optional[str] = None


def scan(target: str, flags: str = "") -> SqlmapResult:
    if not tool_exists("sqlmap"):
        from agent.core.tools_registry import REGISTRY
        _t = REGISTRY["sqlmap"]
        return SqlmapResult(
            target=target,
            error=f"sqlmap not installed. Run: {_t.apt}",
        )

    if not target.startswith("http://") and not target.startswith("https://"):
        target = f"http://{target}"

    command = [
        "sqlmap",
        "-u", target,
        "--batch",
        "--output-dir=/tmp/sqlmap_clawstrike",
        "--level=1",
        "--risk=1",
    ]
    if flags:
        command += flags.split()

    result = runner.run(command, label=f"sqlmap → {target}", timeout=300)

    if result.tool_not_found:
        return SqlmapResult(target=target, error="sqlmap not found")

    vulns, dbs = parse_output(result.clean_output)

    return SqlmapResult(
        target=target,
        vulnerable_params=vulns,
        databases=dbs,
        raw_output=result.clean_output,
    )


def parse_output(raw: str) -> tuple:
    vulnerable_params = []
    databases = []

    for line in raw.splitlines():
        line_s = line.strip()

        if re.search(r"parameter[:\s]+'?\w+'?\s+\(", line_s, re.IGNORECASE):
            vulnerable_params.append(line_s)
        elif "is vulnerable" in line_s.lower():
            vulnerable_params.append(line_s)

        m = re.match(r"\[\*\]\s+(.+)", line_s)
        if m and "database" not in m.group(1).lower():
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
