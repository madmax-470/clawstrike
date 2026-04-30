import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from rich.console import Console
from agent.core.subprocess_utils import runner, tool_exists

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


def scan(target: str, flags: str = "", timeout: int = 120) -> ScanResult:
    if not tool_exists("nmap"):
        from agent.core.tools_registry import REGISTRY
        _t = REGISTRY["nmap"]
        console.print(f"[dim yellow]nmap not found — using manual port scan. Install: {_t.apt}[/dim yellow]")
        from agent.core import manual as _manual
        r = _manual.port_scan(target)
        host_obj = Host(ip=r["host"], hostname="", status="up", ports=r["open_ports"])
        return ScanResult(
            hosts=[host_obj] if r["open_ports"] else [],
            raw_output=_manual.format_port_scan(r),
        )

    xml_tmp = Path(tempfile.mktemp(suffix=".xml", prefix="clawstrike_nmap_"))

    # Strip any output-format flags the caller may have passed
    clean_flags = []
    skip_next = False
    for tok in flags.split():
        if skip_next:
            skip_next = False
            continue
        if tok in ("-oX", "-oN", "-oG", "-oS", "-oA"):
            skip_next = True
            continue
        if tok == "-":
            continue
        clean_flags.append(tok)

    # -oN - streams human-readable output to stdout (displayed live)
    # -oX <file> writes structured XML to a temp file for parsing
    command = ["nmap", "-oN", "-", "-oX", str(xml_tmp)] + clean_flags + [target]

    result = runner.run(command, label=f"nmap → {target}", timeout=timeout)

    hosts = []
    if xml_tmp.exists():
        try:
            hosts = parse_xml(xml_tmp.read_text())
        except Exception:
            pass
        finally:
            try:
                xml_tmp.unlink()
            except OSError:
                pass

    if result.tool_not_found:
        return ScanResult(hosts=[], raw_output="", error="nmap not found")

    if result.timed_out:
        return ScanResult(
            hosts=hosts,
            raw_output=result.clean_output,
            error=f"nmap timed out after {timeout}s",
        )

    if result.returncode != 0 and not hosts:
        return ScanResult(
            hosts=[],
            raw_output=result.clean_output,
            error=result.clean_output or f"nmap exited with code {result.returncode}",
        )

    return ScanResult(hosts=hosts, raw_output=result.clean_output)


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
                            "version": version,
                        })

            hosts.append(Host(ip=ip, hostname=hostname, status=status, ports=ports))

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
                ver = f" — {p['version']}" if p["version"] else ""
                lines.append(f"    {p['port']}/{p['protocol']}  {p['service']}{ver}")
        else:
            lines.append("  No open ports detected")
        lines.append("")

    return "\n".join(lines)
