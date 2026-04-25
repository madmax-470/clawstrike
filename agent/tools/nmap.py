import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Optional
from rich.console import Console

console = Console()


@dataclass
class Host:
    ip: str
    hostname: str
    status: str
    ports: list


@dataclass
class ScanResult:
    hosts: list
    raw_output: str
    error: Optional[str] = None


def scan(target: str, flags: str = "") -> ScanResult:
    # clean any conflicting flags
    clean_flags = [f for f in flags.split() if f not in ["-oX", "-"]]
    command = ["nmap", "-oX", "-"] + clean_flags + [target]

    console.print(f"[dim]running: {' '.join(command)}[/dim]")

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120
        )

        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")

        if result.returncode != 0:
            return ScanResult(
                hosts=[],
                raw_output=stderr,
                error=stderr or f"nmap exited with code {result.returncode}"
            )

        if not stdout.strip():
            return ScanResult(
                hosts=[],
                raw_output="",
                error=f"nmap produced no output. stderr: {stderr}"
            )

        hosts = parse_xml(stdout)

        return ScanResult(
            hosts=hosts,
            raw_output=stdout,
        )

    except subprocess.TimeoutExpired:
        return ScanResult(
            hosts=[],
            raw_output="",
            error="scan timed out after 120 seconds"
        )

    except FileNotFoundError:
        return ScanResult(
            hosts=[],
            raw_output="",
            error="nmap not found — install with: brew install nmap"
        )

    except Exception as e:
        return ScanResult(
            hosts=[],
            raw_output="",
            error=str(e)
        )


def parse_xml(xml_output: str) -> list:
    hosts = []

    try:
        root = ET.fromstring(xml_output)

        for host in root.findall("host"):
            status_elem = host.find("status")
            status = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

            if status != "up":
                continue

            ip = ""
            hostname = ""

            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr", "")

            hostnames = host.find("hostnames")
            if hostnames is not None:
                hn = hostnames.find("hostname")
                if hn is not None:
                    hostname = hn.get("name", "")

            ports = []
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    state_elem = port.find("state")
                    if state_elem is not None and state_elem.get("state") == "open":
                        service_elem = port.find("service")
                        service = ""
                        version = ""
                        if service_elem is not None:
                            service = service_elem.get("name", "")
                            version = service_elem.get("version", "")

                        ports.append({
                            "port": port.get("portid"),
                            "protocol": port.get("protocol"),
                            "service": service,
                            "version": version
                        })

            hosts.append(Host(
                ip=ip,
                hostname=hostname,
                status=status,
                ports=ports
            ))

    except ET.ParseError as e:
        console.print(f"[red]XML parse error: {e}[/red]")

    return hosts


def format_for_agent(result: ScanResult) -> str:
    if result.error:
        return f"SCAN ERROR: {result.error}"

    if not result.hosts:
        return "Scan complete. No live hosts found."

    lines = [f"Scan complete. Found {len(result.hosts)} live host(s):\n"]

    for host in result.hosts:
        lines.append(f"HOST: {host.ip} ({host.hostname or 'no hostname'})")
        if host.ports:
            lines.append(f"  Open ports ({len(host.ports)}):")
            for p in host.ports:
                ver = f" — {p['version']}" if p['version'] else ""
                lines.append(f"    {p['port']}/{p['protocol']}  {p['service']}{ver}")
        else:
            lines.append("  No open ports detected")
        lines.append("")

    return "\n".join(lines)