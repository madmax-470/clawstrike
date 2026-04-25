import subprocess
import re
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console

console = Console()


@dataclass
class Credential:
    host: str
    service: str
    login: str
    password: str


@dataclass
class HydraResult:
    target: str
    service: str
    credentials: list = field(default_factory=list)
    raw_output: str = ""
    error: Optional[str] = None


def scan(target: str, service: str, flags: str = "") -> HydraResult:
    command = ["hydra"]
    if flags:
        command += flags.split()
    command += [f"{service}://{target}"]

    console.print(f"[dim]running: {' '.join(command)}[/dim]")

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
        )

        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
        combined = stdout + stderr

        creds = parse_output(combined, target, service)
        return HydraResult(
            target=target,
            service=service,
            credentials=creds,
            raw_output=combined,
        )

    except subprocess.TimeoutExpired:
        return HydraResult(
            target=target,
            service=service,
            error="hydra timed out after 300 seconds",
        )

    except FileNotFoundError:
        return HydraResult(
            target=target,
            service=service,
            error=(
                "hydra not found — install with:\n"
                "  sudo apt install hydra            # Debian/Ubuntu\n"
                "  brew install hydra                # macOS"
            ),
        )

    except Exception as e:
        return HydraResult(target=target, service=service, error=str(e))


_CRED_PATTERN = re.compile(
    r"\[\d+\]\[[\w-]+\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(.+)",
    re.IGNORECASE,
)


def parse_output(raw: str, target: str, service: str) -> list:
    creds = []
    for line in raw.splitlines():
        m = _CRED_PATTERN.search(line.strip())
        if m:
            creds.append(Credential(
                host=m.group(1),
                service=service,
                login=m.group(2),
                password=m.group(3).strip(),
            ))
    return creds


def format_for_agent(result: HydraResult) -> str:
    if result.error:
        return f"HYDRA ERROR: {result.error}"

    lines = [f"Hydra credential test complete on {result.target} ({result.service}).\n"]

    if result.credentials:
        lines.append(f"VALID CREDENTIALS FOUND ({len(result.credentials)}):")
        for c in result.credentials:
            lines.append(f"  {c.login}:{c.password}  →  {c.host}")
    else:
        lines.append("No valid credentials found.")

    return "\n".join(lines)
