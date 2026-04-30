from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@dataclass
class ToolResult:
    tool: str
    success: bool
    output: str = ""
    error: str = ""


@dataclass
class EngagementState:
    target: str
    profile_name: str
    phase1_passed: bool = False
    phase2_passed: bool = False
    live_hosts: list = field(default_factory=list)
    open_ports: list = field(default_factory=list)
    services: dict = field(default_factory=dict)
    phase3_results: dict = field(default_factory=dict)
    cve_analysis: str = ""
    exploitation_plan: str = ""


class Methodology:
    """
    Runs a phased penetration test engagement.

    Phase 1 — Discovery         (nmap host/port sweep)
    Phase 2 — Service ID        (nmap -sV on open ports)
    Phase 3 — Targeted enum     (per-service tools)
    Phase 4 — CVE / vuln match  (AI analysis)
    Phase 5 — Exploitation plan (AI ranked options, human approved)
    Phase 6 — Report            (summary written to disk)

    Enforcement rules:
    - Never skip a phase.
    - Never say "complete" if any tool in a phase failed.
    - Always show per-tool ✅/❌ status after each phase.
    - Never auto-exploit — Phase 5 presents options and stops.
    """

    def __init__(self, target: str, profile, router):
        from agent.core.scan_profiles import ScanProfile
        self.target = target
        self.profile = profile
        self.router = router
        self.state = EngagementState(
            target=target,
            profile_name=profile.name,
        )

    # ------------------------------------------------------------------ #
    # Phase 1 — Discovery
    # ------------------------------------------------------------------ #
    def run_phase1(self) -> tuple[bool, list, str]:
        """Returns (success, open_port_list, raw_output)."""
        console.print(Panel(
            f"[bold]Phase 1 — Discovery[/bold]\nTarget: {self.target}  Profile: {self.profile.name}",
            style="blue",
        ))

        cmd = self.profile.phase1_cmd.format(target=self.target)
        flags = " ".join(cmd.split()[1:])  # strip "nmap" prefix

        from agent.tools import nmap
        result = nmap.scan(self.target, flags=flags)

        if result.error:
            console.print(f"[red]❌ nmap phase-1: {result.error}[/red]")
            return False, [], result.raw_output

        ports = []
        for host in result.hosts:
            for p in host.ports:
                ports.append(p["port"])

        self.state.live_hosts = result.hosts
        self.state.open_ports = ports
        self.state.phase1_passed = True

        console.print(f"[green]✅ nmap phase-1 — {len(result.hosts)} host(s), {len(ports)} open port(s)[/green]")
        return True, ports, result.raw_output

    # ------------------------------------------------------------------ #
    # Phase 2 — Service Identification
    # ------------------------------------------------------------------ #
    def run_phase2(self, ports: list) -> tuple[bool, dict, str]:
        """Returns (success, services_dict, raw_output).
        services_dict maps port -> {service, version} info.
        """
        console.print(Panel("[bold]Phase 2 — Service Identification[/bold]", style="blue"))

        if not ports:
            console.print("[yellow]⚠ No open ports from Phase 1 — skipping Phase 2[/yellow]")
            return False, {}, ""

        port_str = ",".join(str(p) for p in ports)
        cmd = self.profile.phase2_cmd.format(ports=port_str, target=self.target)
        flags_parts = cmd.split()[1:]
        # Remove -p <ports> and target — we pass target separately
        clean_flags = []
        skip_next = False
        for tok in flags_parts:
            if skip_next:
                skip_next = False
                continue
            if tok == "-p":
                skip_next = True
                continue
            if tok == self.target:
                continue
            clean_flags.append(tok)
        flags = " ".join(clean_flags)

        from agent.tools import nmap
        result = nmap.scan(self.target, flags=f"-p {port_str} {flags}")

        if result.error:
            console.print(f"[red]❌ nmap phase-2: {result.error}[/red]")
            return False, {}, result.raw_output

        services: dict = {}
        for host in result.hosts:
            for p in host.ports:
                services[p["port"]] = {
                    "service": p["service"],
                    "version": p["version"],
                    "protocol": p["protocol"],
                }

        self.state.services = services
        self.state.phase2_passed = True

        _print_services_table(services)
        console.print(f"[green]✅ nmap phase-2 — {len(services)} service(s) identified[/green]")
        return True, services, result.raw_output

    # ------------------------------------------------------------------ #
    # Phase 3 — Targeted Enumeration
    # ------------------------------------------------------------------ #
    def run_phase3(self, services: dict) -> dict:
        """
        Dispatches per-service tools based on what was found.
        Returns dict of {tool_name: ToolResult}.
        """
        console.print(Panel("[bold]Phase 3 — Targeted Enumeration[/bold]", style="blue"))

        results: dict[str, ToolResult] = {}
        timeout = self.profile.phase3_timeout

        port_services = {str(port): info["service"] for port, info in services.items()}

        has_http  = any(s in ("http", "https", "http-alt") for s in port_services.values())
        has_ftp   = any(s == "ftp"  for s in port_services.values())
        has_ssh   = any(s == "ssh"  for s in port_services.values())
        has_smb   = any(s in ("microsoft-ds", "netbios-ssn", "smb") for s in port_services.values())
        has_db    = any(s in ("mysql", "postgresql", "mssql", "oracle") for s in port_services.values())

        if has_http:
            http_ports = [p for p, s in port_services.items()
                          if s in ("http", "https", "http-alt")]
            http_target = _build_http_target(self.target, http_ports)
            results.update(_run_web_tools(http_target, timeout))

        if has_ftp:
            results.update(_run_ftp_tools(self.target))

        if has_ssh:
            results.update(_run_ssh_tools(self.target))

        if has_smb:
            results.update(_run_smb_tools(self.target))

        if has_db:
            results["db_note"] = ToolResult(
                tool="db_note",
                success=True,
                output=f"Database service detected on {self.target} — CVE matching in Phase 4.",
            )

        if not results:
            results["note"] = ToolResult(
                tool="note",
                success=True,
                output="No web/ftp/ssh/smb/db services detected — skipping targeted enumeration.",
            )

        self.state.phase3_results = results
        return results

    def print_phase3_status(self, results: dict) -> bool:
        """Print per-tool ✅/❌ table. Returns True only if ALL tools succeeded."""
        table = Table(title="Phase 3 — Tool Results", show_header=True)
        table.add_column("Tool", style="bold")
        table.add_column("Status")
        table.add_column("Detail")

        all_ok = True
        for name, r in results.items():
            if r.success:
                table.add_row(name, "[green]✅ OK[/green]", r.output[:80] if r.output else "")
            else:
                table.add_row(name, "[red]❌ FAIL[/red]", r.error[:80] if r.error else "")
                all_ok = False

        console.print(table)

        if not all_ok:
            console.print(
                "[yellow]⚠  Phase 3 partial — some tools failed. "
                "Results below are incomplete.[/yellow]"
            )
        else:
            console.print("[green]✅ Phase 3 complete — all tools succeeded[/green]")

        return all_ok

    # ------------------------------------------------------------------ #
    # Phase 4 — CVE / Vulnerability Matching
    # ------------------------------------------------------------------ #
    def run_phase4(self, services: dict, phase3_results: dict) -> str:
        """Uses the smart model to match services/versions to known CVEs."""
        console.print(Panel("[bold]Phase 4 — CVE & Vulnerability Analysis[/bold]", style="blue"))

        service_lines = "\n".join(
            f"  Port {port}: {info['service']} {info['version']}"
            for port, info in services.items()
        )

        enum_summary = "\n".join(
            f"  [{r.tool}]: {'OK' if r.success else 'FAILED'} — {(r.output or r.error)[:200]}"
            for r in phase3_results.values()
        )

        prompt = f"""You are a penetration tester. Analyze these services and enumeration results
for known CVEs and vulnerabilities. Be specific — include CVE IDs where known.

Target: {self.target}

Services found:
{service_lines}

Enumeration results:
{enum_summary}

List the most likely exploitable vulnerabilities in order of severity (Critical → High → Medium).
For each: CVE ID (if known), affected service/version, severity, brief description, and
whether a Metasploit module likely exists."""

        try:
            analysis = self.router.chat(
                "analyze",
                system="You are an expert penetration tester performing authorized security assessments.",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2048,
            )
            self.state.cve_analysis = analysis
            console.print("[green]✅ Phase 4 complete — AI CVE analysis done[/green]")
            console.print(Panel(analysis, title="CVE Analysis", style="dim"))
            return analysis
        except Exception as e:
            err = f"AI analysis failed: {e}"
            console.print(f"[red]❌ Phase 4: {err}[/red]")
            self.state.cve_analysis = err
            return err

    # ------------------------------------------------------------------ #
    # Phase 5 — Exploitation Planning (human-gated)
    # ------------------------------------------------------------------ #
    def present_phase5(self, services: dict, cve_analysis: str) -> None:
        """
        Presents ranked exploitation options via AI.
        NEVER auto-exploits — prints options and stops for human decision.
        """
        console.print(Panel("[bold]Phase 5 — Exploitation Planning[/bold]", style="blue"))

        service_lines = "\n".join(
            f"  Port {port}: {info['service']} {info['version']}"
            for port, info in services.items()
        )

        prompt = f"""You are a senior penetration tester. Based on the vulnerability analysis,
create a ranked exploitation plan.

Target: {self.target}
Services:
{service_lines}

Vulnerability analysis:
{cve_analysis}

Provide a numbered list of exploitation options, ranked by likelihood of success:
1. Metasploit module path (if applicable)
2. Manual technique
3. Tool command
4. Expected outcome
5. Risk level (to target stability)

End with a recommendation for which to attempt first."""

        try:
            plan = self.router.chat(
                "exploit",
                system="You are an expert penetration tester performing authorized security assessments.",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2048,
            )
            self.state.exploitation_plan = plan
            console.print(Panel(plan, title="Exploitation Options (Human Review Required)", style="yellow"))
            console.print(
                "\n[bold yellow]⚠  Phase 5 complete — review options above.[/bold yellow]\n"
                "[dim]ClawStrike does not auto-exploit. Use 'exploit' command to proceed manually.[/dim]"
            )
        except Exception as e:
            console.print(f"[red]❌ Phase 5: AI planning failed: {e}[/red]")

    # ------------------------------------------------------------------ #
    # Phase 6 — Report
    # ------------------------------------------------------------------ #
    def write_report(self) -> Optional[str]:
        """Write engagement summary to disk. Returns path or None on error."""
        from pathlib import Path
        import datetime

        safe_target = self.target.replace("://", "_").replace("/", "_").replace(":", "_")
        report_dir = Path("engagements") / safe_target
        report_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = report_dir / f"report_{ts}.md"

        lines = [
            f"# ClawStrike Engagement Report",
            f"",
            f"**Target:** {self.target}",
            f"**Profile:** {self.profile.name}",
            f"**Date:** {datetime.datetime.now().isoformat()}",
            f"",
            f"## Phase 1 — Discovery",
            f"Open ports: {', '.join(str(p) for p in self.state.open_ports) or 'none'}",
            f"",
            f"## Phase 2 — Services",
        ]
        for port, info in self.state.services.items():
            lines.append(f"- Port {port}: {info['service']} {info['version']}")

        lines += [
            f"",
            f"## Phase 3 — Enumeration",
        ]
        for name, r in self.state.phase3_results.items():
            status = "✅" if r.success else "❌"
            lines.append(f"### {status} {name}")
            lines.append(r.output or r.error or "")

        lines += [
            f"",
            f"## Phase 4 — CVE Analysis",
            self.state.cve_analysis,
            f"",
            f"## Phase 5 — Exploitation Plan",
            self.state.exploitation_plan,
        ]

        try:
            report_path.write_text("\n".join(lines))
            console.print(f"[green]✅ Report saved: {report_path}[/green]")
            return str(report_path)
        except Exception as e:
            console.print(f"[red]❌ Report write failed: {e}[/red]")
            return None

    # ------------------------------------------------------------------ #
    # Orchestrator
    # ------------------------------------------------------------------ #
    def run(self) -> dict:
        """Run Phases 1-5 in strict order. Return engagement state dict."""
        # Phase 1
        ok1, ports, _ = self.run_phase1()
        if not ok1:
            console.print("[red]Phase 1 failed — cannot continue engagement.[/red]")
            return {"error": "phase1_failed", "state": self.state}

        # Phase 2
        ok2, services, _ = self.run_phase2(ports)
        if not ok2 or not services:
            console.print("[red]Phase 2 failed or no services identified — cannot continue.[/red]")
            return {"error": "phase2_failed", "state": self.state}

        # Phase 3
        p3_results = self.run_phase3(services)
        self.print_phase3_status(p3_results)

        # Phase 4
        cve_analysis = self.run_phase4(services, p3_results)

        # Phase 5 (never auto-exploits)
        self.present_phase5(services, cve_analysis)

        # Phase 6
        report_path = self.write_report()

        return {
            "state": self.state,
            "report": report_path,
        }


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

def _build_http_target(target: str, http_ports: list) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    port = http_ports[0] if http_ports else "80"
    scheme = "https" if port in ("443", "8443") else "http"
    return f"{scheme}://{target}:{port}"


def _run_web_tools(target: str, timeout: int) -> dict:
    results = {}

    from agent.tools import gobuster, nikto

    gb = gobuster.scan(target)
    results["gobuster"] = ToolResult(
        tool="gobuster",
        success=gb.error is None,
        output=gobuster.format_for_agent(gb),
        error=gb.error or "",
    )

    nk = nikto.scan(target)
    results["nikto"] = ToolResult(
        tool="nikto",
        success=nk.error is None,
        output=nikto.format_for_agent(nk),
        error=nk.error or "",
    )

    return results


def _run_ftp_tools(target: str) -> dict:
    from agent.core.subprocess_utils import run_tool, tool_exists
    results = {}

    # Anonymous login check
    stdout, stderr, rc = run_tool(
        ["ftp", "-n", "-v", target],
        timeout=10,
    )
    anon_ok = "230" in stdout or "anonymous" in stdout.lower()
    results["ftp_anon"] = ToolResult(
        tool="ftp_anon",
        success=True,
        output=f"Anonymous FTP {'ALLOWED' if anon_ok else 'denied'} on {target}",
    )

    # vsftpd 2.3.4 backdoor check (port 6200)
    import socket
    backdoor = False
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((target, 6200))
        backdoor = True
        s.close()
    except OSError:
        pass

    results["ftp_backdoor"] = ToolResult(
        tool="ftp_backdoor",
        success=True,
        output=(
            f"vsftpd 2.3.4 backdoor port 6200: {'OPEN — potential backdoor!' if backdoor else 'closed'}"
        ),
    )

    return results


def _run_ssh_tools(target: str) -> dict:
    from agent.core.subprocess_utils import run_tool, tool_exists
    results = {}

    if tool_exists("ssh-audit"):
        stdout, stderr, rc = run_tool(["ssh-audit", target], timeout=30)
        results["ssh_audit"] = ToolResult(
            tool="ssh_audit",
            success=rc == 0,
            output=stdout[:2000] if rc == 0 else "",
            error=stderr[:500] if rc != 0 else "",
        )
    else:
        results["ssh_audit"] = ToolResult(
            tool="ssh_audit",
            success=False,
            error="ssh-audit not installed — run: pip install ssh-audit",
        )

    return results


def _run_smb_tools(target: str) -> dict:
    from agent.core.subprocess_utils import run_tool, tool_exists
    results = {}

    if tool_exists("enum4linux"):
        stdout, stderr, rc = run_tool(["enum4linux", "-a", target], timeout=60)
        results["enum4linux"] = ToolResult(
            tool="enum4linux",
            success=rc == 0,
            output=stdout[:3000] if rc == 0 else "",
            error=stderr[:500] if rc != 0 else "",
        )
    else:
        results["enum4linux"] = ToolResult(
            tool="enum4linux",
            success=False,
            error="enum4linux not installed — run: apt install enum4linux",
        )

    return results


def _print_services_table(services: dict) -> None:
    table = Table(title="Services Identified", show_header=True)
    table.add_column("Port", style="cyan")
    table.add_column("Protocol")
    table.add_column("Service", style="bold")
    table.add_column("Version")

    for port, info in services.items():
        table.add_row(
            str(port),
            info.get("protocol", ""),
            info.get("service", ""),
            info.get("version", ""),
        )

    console.print(table)
