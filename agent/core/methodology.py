import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from agent.core.intelligence import intelligence, Answer
from agent.core.session import EngagementSession, ExploitOption, ENGAGEMENTS_DIR

_ENGAGEMENTS_DIR = Path(ENGAGEMENTS_DIR)

_PHASE4_SYSTEM_PROMPT = """\
You are a vulnerability analyst. Given a list of services and versions found \
on a target, identify exploitable vulnerabilities.

You MUST respond with valid JSON only.
No markdown. No explanation. Just JSON.

Format:
{
  "exploits": [
    {
      "title": "vsftpd 2.3.4 Backdoor",
      "cve": "CVE-2011-2523",
      "cvss": 10.0,
      "port": 21,
      "service": "ftp",
      "version": "2.3.4",
      "msf_module": "exploit/unix/ftp/vsftpd_234_backdoor",
      "manual_cmd": "nc -v {target} 6200",
      "confidence": "high",
      "notes": "Backdoor triggered by :) in username"
    }
  ]
}

Sort by cvss descending.
Include msf_module if a Metasploit module exists.
Include manual_cmd if exploit can be done manually.
Only include exploits you are confident about.
If no exploits known for a service, omit it.

STRICT JSON RULES:
- No trailing commas
- All strings must use double quotes
- No single quotes anywhere
- No comments inside JSON
- No newlines inside string values (use \\n if needed)
- Escape any double quotes inside strings
- Return ONLY the JSON object
- Do not wrap in markdown code blocks\
"""

console = Console()


@dataclass
class ToolResult:
    tool: str          # question name (e.g. "what_web_paths_exist")
    success: bool
    output: str = ""
    error: str = ""
    method_used: str = ""   # which method answered it (e.g. "gobuster", "manual_urllib")


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
    exploit_options: list = field(default_factory=list)


class Methodology:
    """
    Runs a phased penetration test engagement.

    Phase 1 — Discovery         (answer: is_host_alive + what_ports_open)
    Phase 2 — Service ID        (answer: what_services_on_ports)
    Phase 3 — Targeted enum     (answer: service-specific questions)
    Phase 4 — CVE / vuln match  (answer: what_cves_apply)
    Phase 5 — Exploitation plan (answer: what_exploits_available)
    Phase 6 — Report            (summary written to disk)

    The agent thinks in questions, not tools.
    The question is always the goal; the tool used to answer it is an
    implementation detail shown in [brackets] but never the primary focus.

    Enforcement rules:
    - Never skip a phase.
    - Never say "complete" if any question could not be answered.
    - Always show per-question ✅/❌ status after each phase.
    - Never auto-exploit — Phase 5 presents options and stops.
    """

    def __init__(self, target: str, profile, router):
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
            f"[bold]Phase 1 — Discovery[/bold]\n"
            f"Target: {self.target}  Profile: {self.profile.name}",
            style="blue",
        ))

        # answering: is_host_alive
        alive_answer = intelligence.answer("is_host_alive", self.target, {})
        if not alive_answer.alive:
            console.print(
                "[yellow]⚠ Host may be down or blocking all probes — continuing anyway[/yellow]"
            )

        # answering: what_ports_open
        context = {
            "phase1_cmd": self.profile.phase1_cmd.format(target=self.target),
            "top_ports": 100,
        }
        port_answer = intelligence.answer("what_ports_open", self.target, context)

        if not port_answer.success:
            console.print(f"[red]❌ port discovery: {port_answer.error}[/red]")
            return False, [], ""

        ports = port_answer.ports
        self.state.live_hosts = port_answer.data.get("hosts", [])
        self.state.open_ports = ports
        self.state.phase1_passed = True

        console.print(
            f"[green]✅ Phase 1 — {len(ports)} open port(s) discovered "
            f"[{port_answer.method_used}][/green]"
        )
        return True, ports, ""

    # ------------------------------------------------------------------ #
    # Phase 2 — Service Identification
    # ------------------------------------------------------------------ #
    def run_phase2(self, ports: list) -> tuple[bool, dict, str]:
        """Returns (success, services_dict, raw_output)."""
        console.print(Panel("[bold]Phase 2 — Service Identification[/bold]", style="blue"))

        if not ports:
            console.print("[yellow]⚠ No open ports from Phase 1 — skipping Phase 2[/yellow]")
            return False, {}, ""

        # answering: what_services_on_ports (all ports in one scan for efficiency)
        context = {
            "ports": ports,
            "profile_cmd": self.profile.phase2_cmd,
        }
        answer = intelligence.answer("what_services_on_ports", self.target, context)

        if not answer.success:
            console.print(f"[red]❌ service identification: {answer.error}[/red]")
            return False, {}, ""

        services = answer.services
        self.state.services = services
        self.state.phase2_passed = True

        _print_services_table(services)
        console.print(
            f"[green]✅ Phase 2 — {len(services)} service(s) identified "
            f"[{answer.method_used}][/green]"
        )
        return True, services, ""

    # ------------------------------------------------------------------ #
    # Phase 3 — Targeted Enumeration
    # ------------------------------------------------------------------ #
    def run_phase3(self, services: dict) -> dict:
        """
        Asks service-specific intelligence questions based on what Phase 2 found.
        Returns dict of {question_name: ToolResult}.
        """
        console.print(Panel("[bold]Phase 3 — Targeted Enumeration[/bold]", style="blue"))

        results: dict[str, ToolResult] = {}
        port_services = {str(port): info["service"] for port, info in services.items()}

        has_http = any(s in ("http", "https", "http-alt") for s in port_services.values())
        has_ftp  = any(s == "ftp"  for s in port_services.values())
        has_ssh  = any(s == "ssh"  for s in port_services.values())
        has_smb  = any(s in ("microsoft-ds", "netbios-ssn", "smb") for s in port_services.values())
        has_db   = any(s in ("mysql", "postgresql", "mssql", "oracle") for s in port_services.values())

        if has_http:
            http_ports = [p for p, s in port_services.items()
                          if s in ("http", "https", "http-alt")]
            http_port = int(http_ports[0]) if http_ports else 80
            http_target = _build_http_target(self.target, http_ports)
            ctx = {"port": http_port}

            for question in ("what_web_paths_exist", "what_web_tech", "is_web_vulnerable"):
                ans = intelligence.answer(question, http_target, ctx)
                results[question] = _answer_to_result(question, ans)

        if has_ftp:
            ftp_port = next(
                (int(p) for p, s in port_services.items() if s == "ftp"), 21
            )
            ans = intelligence.answer(
                "is_ftp_anonymous", self.target, {"port": ftp_port}
            )
            results["is_ftp_anonymous"] = _answer_to_result("is_ftp_anonymous", ans)

        if has_ssh:
            ssh_port = next(
                (int(p) for p, s in port_services.items() if s == "ssh"), 22
            )
            ans = intelligence.answer(
                "what_ssh_ciphers", self.target, {"port": ssh_port}
            )
            results["what_ssh_ciphers"] = _answer_to_result("what_ssh_ciphers", ans)

        if has_smb:
            ans = intelligence.answer("is_smb_vulnerable", self.target, {})
            results["is_smb_vulnerable"] = _answer_to_result("is_smb_vulnerable", ans)

        if has_db:
            db_service = next(
                (s for s in port_services.values()
                 if s in ("mysql", "postgresql", "mssql", "oracle")),
                "mysql",
            )
            db_port = next(
                (int(p) for p, s in port_services.items() if s == db_service), 3306
            )
            ans = intelligence.answer(
                "is_db_default_creds", self.target,
                {"service": db_service, "port": db_port}
            )
            results["is_db_default_creds"] = _answer_to_result("is_db_default_creds", ans)

        if not results:
            results["note"] = ToolResult(
                tool="note", success=True, method_used="n/a",
                output="No web/ftp/ssh/smb/db services detected — skipping targeted enumeration.",
            )

        self.state.phase3_results = results
        return results

    def print_phase3_status(self, results: dict) -> bool:
        """Print per-question ✅/❌ table. Returns True only if ALL questions were answered."""
        table = Table(title="Phase 3 — Questions Answered", show_header=True)
        table.add_column("Question", style="bold")
        table.add_column("Status")
        table.add_column("Method", style="dim")
        table.add_column("Detail")

        all_ok = True
        for name, r in results.items():
            if r.success:
                table.add_row(
                    name,
                    "[green]✅ answered[/green]",
                    r.method_used,
                    r.output[:80] if r.output else "",
                )
            else:
                table.add_row(
                    name,
                    "[red]❌ failed[/red]",
                    r.method_used,
                    r.error[:80] if r.error else "",
                )
                all_ok = False

        console.print(table)

        if not all_ok:
            console.print(
                "[yellow]⚠  Phase 3 partial — some questions could not be answered. "
                "Results may be incomplete.[/yellow]"
            )
        else:
            console.print("[green]✅ Phase 3 complete — all questions answered[/green]")

        return all_ok

    # ------------------------------------------------------------------ #
    # Phase 4 — CVE / Vulnerability Matching
    # ------------------------------------------------------------------ #
    def run_phase4(self, services: dict, phase3_results: dict,
                   session: EngagementSession) -> str:
        """Calls Claude with a JSON-only prompt and parses exploits into session."""
        console.print(Panel("[bold]Phase 4 — CVE & Vulnerability Analysis[/bold]", style="blue"))

        service_lines = "\n".join(
            f"  Port {port}: {info.get('service', '')} {info.get('version', '')}"
            for port, info in services.items()
        )
        phase3_summary = "\n".join(
            f"  [{r.tool}] [{r.method_used}]: "
            f"{'answered' if r.success else 'FAILED'} — "
            f"{(r.output or r.error)[:200]}"
            for r in phase3_results.values()
        )
        user_prompt = (
            f"Target: {self.target}\n\nServices:\n{service_lines}\n\n"
            f"Enumeration findings:\n{phase3_summary}"
        )

        try:
            raw = self.router.chat(
                "analyze",
                system=_PHASE4_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
                max_tokens=2048,
            )
        except Exception as e:
            console.print(f"[red]❌ Phase 4: AI call failed — {e}[/red]")
            self.state.cve_analysis = str(e)
            return str(e)

        parse_exploit_options(raw, session)
        self.state.cve_analysis = raw
        self.state.exploit_options = [vars(o) for o in session.exploit_options]

        n = len(session.exploit_options)
        if n:
            console.print(f"[green]✅ Phase 4 complete — {n} exploit option(s) identified[/green]")
        else:
            console.print("[yellow]⚠ Phase 4 complete — no exploitable vulnerabilities identified[/yellow]")

        return raw

    # ------------------------------------------------------------------ #
    # Phase 5 — Exploitation Planning (human-gated)
    # ------------------------------------------------------------------ #
    def present_phase5(self, session: EngagementSession) -> None:
        """
        Reads exploit options already parsed into session by Phase 4.
        Presents them for human review. NEVER auto-exploits.
        """
        console.print(Panel("[bold]Phase 5 — Exploitation Planning[/bold]", style="blue"))

        if not session.exploit_options:
            console.print("[yellow]⚠ No exploits identified for this target[/yellow]")
            return

        console.print(f"\n[bold]{len(session.exploit_options)} exploit option(s):[/bold]\n")

        risk_icons = {(9, 11): "🔴", (7, 9): "🟠", (0, 7): "🟡"}
        for opt in session.exploit_options:
            icon = next(
                (ic for (lo, hi), ic in risk_icons.items() if lo <= opt.cvss < hi),
                "🟡",
            )
            msf_tag = "[green]MSF ✓[/green]" if opt.msf_module else "[dim]manual only[/dim]"
            console.print(f"{icon} [bold][{opt.number}][/bold] {opt.title}")
            console.print(f"     CVE: {opt.cve}  CVSS: {opt.cvss}  Port: {opt.port}/{opt.service}")
            console.print(f"     {msf_tag}  Confidence: {opt.confidence}")
            console.print(f"     [dim]{opt.notes}[/dim]\n")

        self.state.exploitation_plan = (
            f"{len(session.exploit_options)} option(s) identified — see session for details"
        )

        console.print(
            "[bold yellow]⚠  Phase 5 complete — review options above.[/bold yellow]\n"
            "[dim]Use 'exploit <n>' · 'exploit all' · 'skip <n>' · 'manual <n>'[/dim]"
        )

    # ------------------------------------------------------------------ #
    # Phase 6 — Report
    # ------------------------------------------------------------------ #
    def write_report(self) -> Optional[str]:
        """Write engagement summary to disk. Returns path or None on error."""
        import datetime

        safe_target = (
            self.target.replace("://", "_").replace("/", "_").replace(":", "_")
        )
        report_dir = _ENGAGEMENTS_DIR / safe_target
        report_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = report_dir / f"report_{ts}.md"

        lines = [
            "# ClawStrike Engagement Report",
            "",
            f"**Target:** {self.target}",
            f"**Profile:** {self.profile.name}",
            f"**Date:** {datetime.datetime.now().isoformat()}",
            "",
            "## Phase 1 — Discovery",
            f"Open ports: {', '.join(str(p) for p in self.state.open_ports) or 'none'}",
            "",
            "## Phase 2 — Services",
        ]
        for port, info in self.state.services.items():
            lines.append(f"- Port {port}: {info['service']} {info['version']}")

        lines += ["", "## Phase 3 — Enumeration"]
        for name, r in self.state.phase3_results.items():
            status = "✅" if r.success else "❌"
            method = f"  [{r.method_used}]" if r.method_used else ""
            lines.append(f"### {status} {name}{method}")
            lines.append(r.output or r.error or "")

        lines += [
            "",
            "## Phase 4 — CVE Analysis",
            self.state.cve_analysis,
            "",
            "## Phase 5 — Exploitation Plan",
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
    def run(self, session: EngagementSession) -> dict:
        """Run Phases 1-6 in strict order. Return engagement state dict."""
        ok1, ports, _ = self.run_phase1()
        if not ok1:
            console.print("[red]Phase 1 failed — cannot continue engagement.[/red]")
            return {"error": "phase1_failed", "state": self.state}

        ok2, services, _ = self.run_phase2(ports)
        if not ok2 or not services:
            console.print(
                "[red]Phase 2 failed or no services identified — cannot continue.[/red]"
            )
            return {"error": "phase2_failed", "state": self.state}

        # keep session in sync with phase 1-2 discoveries
        session.open_ports = self.state.open_ports
        session.services = {
            str(p): {"service": info.get("service", ""), "version": info.get("version", "")}
            for p, info in services.items()
        }

        p3_results = self.run_phase3(services)
        self.print_phase3_status(p3_results)

        self.run_phase4(services, p3_results, session)
        self.present_phase5(session)

        report_path = self.write_report()

        return {
            "state": self.state,
            "session": session,
            "report": report_path,
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_exploit_options(claude_response: str, session: EngagementSession) -> None:
    """Parse Claude's JSON exploit response and populate session.exploit_options.

    Tries four progressively more forgiving extraction methods so that
    minor formatting deviations from Claude don't lose all exploit data.
    """
    text = claude_response.strip()

    # Method 1: direct parse
    try:
        data = json.loads(text)
        _load_exploits(data, session)
        return
    except json.JSONDecodeError:
        pass

    # Method 2: extract from markdown fences  ```json ... ```
    json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if json_match:
        try:
            data = json.loads(json_match.group(1))
            _load_exploits(data, session)
            return
        except json.JSONDecodeError:
            pass

    # Method 3: first { to last }
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            data = json.loads(text[start : end + 1])
            _load_exploits(data, session)
            return
        except json.JSONDecodeError:
            pass

    # Method 4: strip trailing commas + control characters, then retry
    cleaned = re.sub(r",\s*([}\]])", r"\1", text)
    cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", cleaned)
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1:
        try:
            data = json.loads(cleaned[start : end + 1])
            _load_exploits(data, session)
            return
        except json.JSONDecodeError as e:
            console.print(f"[red]CVE parsing failed after all attempts: {e}[/red]")
            console.print("[dim]Continuing without structured exploit options[/dim]")
            return

    console.print("[red]CVE parsing failed: no JSON object found in response[/red]")
    console.print("[dim]Continuing without structured exploit options[/dim]")


def _load_exploits(data: dict, session: EngagementSession) -> None:
    """Load exploits from a parsed JSON dict into session."""
    exploits = data.get("exploits", [])
    if not exploits:
        console.print("[yellow]⚠ Claude returned no exploits for these services[/yellow]")
        return

    for item in exploits:
        try:
            option = ExploitOption(
                number=0,
                title=str(item.get("title", "")),
                cve=str(item.get("cve", "")),
                cvss=float(item.get("cvss", 0)),
                port=int(item.get("port", 0)),
                service=str(item.get("service", "")),
                version=str(item.get("version", "")),
                msf_module=str(item.get("msf_module", "")),
                manual_cmd=str(item.get("manual_cmd", "")),
                confidence=str(item.get("confidence", "low")),
                notes=str(item.get("notes", "")),
            )
            session.add_exploit(option)
        except (ValueError, TypeError) as e:
            console.print(f"[yellow]Skipping malformed exploit entry: {e}[/yellow]")

    console.print(f"[green]✅ {len(session.exploit_options)} exploit option(s) loaded[/green]")


def _answer_to_result(question: str, ans: Answer) -> ToolResult:
    """Convert an Answer into a ToolResult for phase status tracking."""
    output = ""
    if ans.success:
        d = ans.data
        if "paths" in d:
            output = f"{len(d['paths'])} path(s) found"
        elif "tech" in d:
            output = ", ".join(d["tech"][:5]) or "none detected"
        elif "vulnerabilities" in d:
            output = f"{len(d['vulnerabilities'])} finding(s)"
        elif "weak_ciphers" in d:
            output = f"{len(d['weak_ciphers'])} weak cipher(s)"
        elif "anonymous" in d:
            output = f"anonymous login {'ALLOWED' if d['anonymous'] else 'denied'}"
        elif "vulnerable" in d:
            output = f"default creds {'FOUND' if d['vulnerable'] else 'not found'}"
        elif "raw" in d:
            output = d["raw"][:200]
        else:
            output = str(d)[:200]

    return ToolResult(
        tool=question,
        success=ans.success,
        output=output,
        error=ans.error,
        method_used=ans.method_used,
    )


def _build_http_target(target: str, http_ports: list) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    port = http_ports[0] if http_ports else "80"
    scheme = "https" if port in ("443", "8443") else "http"
    return f"{scheme}://{target}:{port}"


def _print_services_table(services: dict) -> None:
    from rich.table import Table
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
