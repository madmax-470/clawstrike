from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console

console = Console()


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class Attempt:
    method: str
    success: bool
    error: str = ""


@dataclass
class Answer:
    question: str
    target: str
    success: bool
    method_used: str
    data: dict = field(default_factory=dict)
    error: str = ""
    attempts: list = field(default_factory=list)

    # Typed accessors — callers use these instead of indexing .data directly
    @property
    def alive(self) -> bool:
        return self.data.get("alive", False)

    @property
    def ports(self) -> list:
        return self.data.get("ports", [])

    @property
    def services(self) -> dict:
        return self.data.get("services", {})

    @property
    def service(self) -> str:
        return self.data.get("service", "")

    @property
    def version(self) -> str:
        return self.data.get("version", "")

    @property
    def paths(self) -> list:
        return self.data.get("paths", [])

    @property
    def tech(self) -> list:
        return self.data.get("tech", [])

    @property
    def vulnerabilities(self) -> list:
        return self.data.get("vulnerabilities", [])

    @property
    def weak_ciphers(self) -> list:
        return self.data.get("weak_ciphers", [])

    @property
    def anonymous(self) -> bool:
        return self.data.get("anonymous", False)

    @property
    def vulnerable(self) -> bool:
        return self.data.get("vulnerable", False)

    @property
    def analysis(self) -> str:
        return self.data.get("analysis", "")

    @property
    def plan(self) -> str:
        return self.data.get("plan", "")


# ── PentestIntelligence ───────────────────────────────────────────────────────

class PentestIntelligence:
    """
    Information-centric intelligence layer.

    Thinks in questions and answers, not tool names.
    Tries multiple methods per question in preference order.
    Falls back automatically. Never gives up until all methods are exhausted.
    Reports which method ultimately answered the question.
    """

    def answer(self, question: str, target: str, context: dict = None) -> Answer:
        """
        Given a question about a target, tries every available method
        to answer it. Returns a structured Answer regardless of which
        method succeeded.
        """
        if context is None:
            context = {}

        console.print(f"\n[dim cyan]need: {question} on {target}[/dim cyan]")

        handler = getattr(self, f"_answer_{question}", None)
        if handler is None:
            return Answer(
                question=question, target=target, success=False,
                method_used="none",
                error=f"Unknown question: {question}",
            )

        return handler(target, context)

    # ── Logging helpers ───────────────────────────────────────────────────────

    def _trying(self, method: str) -> None:
        console.print(f"[dim]  trying: {method}[/dim]")

    def _ok(self, method: str, detail: str = "") -> None:
        suffix = f": {detail}" if detail else ""
        console.print(f"[green]  ✅ {method} answered{suffix}[/green]")

    def _fail(self, method: str, reason: str = "") -> None:
        suffix = f": {reason}" if reason else ""
        console.print(f"[dim red]  ❌ {method} failed{suffix}[/dim red]")

    # ── is_host_alive ─────────────────────────────────────────────────────────

    def _answer_is_host_alive(self, target: str, context: dict) -> Answer:
        attempts = []

        # Method 1: ping
        self._trying("ping (icmp)")
        try:
            import subprocess
            r = subprocess.run(
                ["ping", "-c", "1", "-W", "1", target],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3,
            )
            if r.returncode == 0:
                self._ok("ping", "host responded")
                return Answer("is_host_alive", target, True, "ping",
                              {"alive": True}, attempts=[Attempt("ping", True)])
            attempts.append(Attempt("ping", False, f"exit {r.returncode}"))
            self._fail("ping", "no response")
        except Exception as e:
            attempts.append(Attempt("ping", False, str(e)))
            self._fail("ping", str(e))

        # Method 2: nmap -sn
        self._trying("nmap -sn")
        if _tool_exists("nmap"):
            try:
                from agent.core.subprocess_utils import run_tool
                stdout, _, _ = run_tool(["nmap", "-sn", target], timeout=15)
                if "Host is up" in stdout:
                    self._ok("nmap -sn", "host is up")
                    return Answer("is_host_alive", target, True, "nmap -sn",
                                  {"alive": True},
                                  attempts=attempts + [Attempt("nmap -sn", True)])
                attempts.append(Attempt("nmap -sn", False, "host not up"))
                self._fail("nmap -sn", "host not up in output")
            except Exception as e:
                attempts.append(Attempt("nmap -sn", False, str(e)))
                self._fail("nmap -sn", str(e))
        else:
            self._fail("nmap -sn", "not installed")
            attempts.append(Attempt("nmap -sn", False, "not installed"))

        # Methods 3-5: tcp connect on common ports
        for port in (80, 443, 22):
            self._trying(f"tcp connect :{port}")
            alive, err = _tcp_probe(target, port, timeout=2)
            if alive:
                self._ok(f"tcp connect :{port}", f"port {port} open")
                return Answer("is_host_alive", target, True, f"tcp_connect:{port}",
                              {"alive": True},
                              attempts=attempts + [Attempt(f"tcp:{port}", True)])
            attempts.append(Attempt(f"tcp:{port}", False, err))
            self._fail(f"tcp connect :{port}", err)

        # No probe responded — host is probably down
        self._ok("exhausted", "host appears down")
        return Answer(
            "is_host_alive", target, True, "exhausted",
            {"alive": False},
            error="No probe responded — host may be down or blocking all probes",
            attempts=attempts,
        )

    # ── what_ports_open ───────────────────────────────────────────────────────

    def _answer_what_ports_open(self, target: str, context: dict) -> Answer:
        attempts = []
        top_n = context.get("top_ports", 100)
        phase1_cmd = context.get("phase1_cmd", "")

        # Method 1: nmap
        self._trying(f"nmap --top-ports {top_n}")
        if _tool_exists("nmap"):
            try:
                from agent.tools.nmap import scan as nmap_scan
                flags = ""
                if phase1_cmd:
                    toks = phase1_cmd.split()
                    flags = " ".join(t for t in toks[1:] if t != target)
                if not flags:
                    flags = f"--top-ports {top_n}"
                result = nmap_scan(target, flags=flags, timeout=120)
                ports = _extract_ports(result.hosts)
                if not result.error or ports:
                    self._ok("nmap", f"ports {','.join(str(p) for p in ports) or 'none'}")
                    return Answer("what_ports_open", target, True, "nmap",
                                  {"ports": ports, "hosts": result.hosts},
                                  attempts=attempts + [Attempt("nmap", True)])
                attempts.append(Attempt("nmap", False, result.error or "no results"))
                self._fail("nmap", result.error or "no results")
            except Exception as e:
                attempts.append(Attempt("nmap", False, str(e)))
                self._fail("nmap", str(e))
        else:
            self._fail("nmap", "not installed")
            attempts.append(Attempt("nmap", False, "not installed"))

        # Method 2: masscan
        self._trying(f"masscan --top-ports {top_n}")
        if _tool_exists("masscan"):
            try:
                from agent.core.subprocess_utils import runner
                result = runner.run(
                    ["masscan", "--top-ports", str(top_n), target, "--rate=1000"],
                    label=f"masscan → {target}",
                    timeout=60,
                )
                ports = _parse_masscan_ports(result.clean_output)
                self._ok("masscan", f"ports {','.join(str(p) for p in ports) or 'none'}")
                return Answer("what_ports_open", target, True, "masscan",
                              {"ports": ports},
                              attempts=attempts + [Attempt("masscan", True)])
            except Exception as e:
                attempts.append(Attempt("masscan", False, str(e)))
                self._fail("masscan", str(e))
        else:
            self._fail("masscan", "not installed")
            attempts.append(Attempt("masscan", False, "not installed"))

        # Method 3: manual socket sweep (top common ports)
        self._trying("manual socket sweep")
        common = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                  443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        open_ports = _socket_sweep(target, common, timeout=1)
        self._ok("socket sweep", f"ports {','.join(str(p) for p in open_ports) or 'none'}")
        return Answer("what_ports_open", target, True, "socket_sweep",
                      {"ports": open_ports},
                      attempts=attempts + [Attempt("socket_sweep", True)])

    # ── what_services_on_ports (plural — phase 2 efficiency) ─────────────────

    def _answer_what_services_on_ports(self, target: str, context: dict) -> Answer:
        """Identifies services on a list of known-open ports in one scan."""
        ports = context.get("ports", [])
        attempts = []

        if not ports:
            return Answer("what_services_on_ports", target, False, "none",
                          error="context must include 'ports' list")

        port_str = ",".join(str(p) for p in ports)
        profile_cmd = context.get("profile_cmd", "")

        # Derive extra flags from profile phase2 command
        extra_flags = ""
        if profile_cmd:
            toks = profile_cmd.split()
            skip = False
            parts = []
            for tok in toks[1:]:
                if skip:
                    skip = False
                    continue
                if tok == "-p":
                    skip = True
                    continue
                if tok in ("{ports}", target):
                    continue
                parts.append(tok)
            extra_flags = " ".join(parts)

        # Method 1: nmap -sV (all ports at once)
        self._trying(f"nmap -sV [{port_str}]")
        if _tool_exists("nmap"):
            try:
                from agent.tools.nmap import scan as nmap_scan
                flags = f"-p {port_str} {extra_flags}".strip() or f"-sV -p {port_str}"
                result = nmap_scan(target, flags=flags, timeout=120)
                services = {}
                for host in result.hosts:
                    for p in host.ports:
                        services[p["port"]] = {
                            "service": p.get("service", ""),
                            "version": p.get("version", ""),
                            "protocol": p.get("protocol", "tcp"),
                        }
                if not result.error or services:
                    self._ok("nmap -sV", f"{len(services)} service(s) identified")
                    return Answer("what_services_on_ports", target, True, "nmap -sV",
                                  {"services": services},
                                  attempts=attempts + [Attempt("nmap -sV", True)])
                attempts.append(Attempt("nmap -sV", False, result.error or "no results"))
                self._fail("nmap -sV", result.error or "no results")
            except Exception as e:
                attempts.append(Attempt("nmap -sV", False, str(e)))
                self._fail("nmap -sV", str(e))
        else:
            self._fail("nmap -sV", "not installed")
            attempts.append(Attempt("nmap -sV", False, "not installed"))

        # Method 2: banner grab per port
        self._trying("banner grab per port")
        services = {}
        for port in ports:
            banner, _ = _banner_grab(target, int(port), timeout=3)
            svc, ver = _guess_service_from_banner(banner, int(port))
            services[str(port)] = {
                "service": svc,
                "version": ver,
                "protocol": "tcp",
            }
        self._ok("banner grab", f"{len(services)} port(s) probed")
        return Answer("what_services_on_ports", target, True, "banner_grab",
                      {"services": services},
                      attempts=attempts + [Attempt("banner_grab", True)])

    # ── what_service_on_port (singular) ───────────────────────────────────────

    def _answer_what_service_on_port(self, target: str, context: dict) -> Answer:
        port = context.get("port")
        if port is None:
            return Answer("what_service_on_port", target, False, "none",
                          error="context must include 'port'")
        attempts = []

        # Method 1: nmap -sV
        self._trying(f"nmap -sV -p {port}")
        if _tool_exists("nmap"):
            try:
                from agent.tools.nmap import scan as nmap_scan
                result = nmap_scan(target, flags=f"-sV -p {port}", timeout=60)
                for host in result.hosts:
                    for p in host.ports:
                        if str(p["port"]) == str(port):
                            svc, ver = p.get("service", ""), p.get("version", "")
                            self._ok("nmap -sV", f"{svc} {ver}".strip())
                            return Answer("what_service_on_port", target, True, "nmap -sV",
                                          {"service": svc, "version": ver, "port": port},
                                          attempts=attempts + [Attempt("nmap -sV", True)])
                attempts.append(Attempt("nmap -sV", False, "port not in results"))
                self._fail("nmap -sV", "port not in results")
            except Exception as e:
                attempts.append(Attempt("nmap -sV", False, str(e)))
                self._fail("nmap -sV", str(e))
        else:
            self._fail("nmap -sV", "not installed")
            attempts.append(Attempt("nmap -sV", False, "not installed"))

        # Method 2: banner grab
        self._trying(f"banner grab :{port}")
        banner, err = _banner_grab(target, int(port), timeout=3)
        if banner:
            svc, ver = _guess_service_from_banner(banner, int(port))
            self._ok("banner grab", f"{svc} {ver}".strip() or banner[:40])
            return Answer("what_service_on_port", target, True, "banner_grab",
                          {"service": svc, "version": ver, "banner": banner, "port": port},
                          attempts=attempts + [Attempt("banner_grab", True)])
        attempts.append(Attempt("banner_grab", False, err))
        self._fail("banner grab", err)

        # Method 3: curl (web ports)
        if int(port) in (80, 443, 8080, 8443, 8000, 8888):
            scheme = "https" if int(port) in (443, 8443) else "http"
            self._trying(f"curl {scheme}://{target}:{port}")
            if _tool_exists("curl"):
                try:
                    from agent.core.subprocess_utils import run_tool
                    stdout, _, rc = run_tool(
                        ["curl", "-sI", "--max-time", "5", f"{scheme}://{target}:{port}"],
                        timeout=10,
                    )
                    if stdout:
                        server = _extract_server_header(stdout)
                        self._ok("curl", f"{scheme} {server}".strip())
                        return Answer("what_service_on_port", target, True, "curl",
                                      {"service": scheme, "version": server, "port": port},
                                      attempts=attempts + [Attempt("curl", True)])
                except Exception as e:
                    self._fail("curl", str(e))

        return Answer("what_service_on_port", target, False, "exhausted",
                      {"service": "unknown", "version": "", "port": port},
                      error="Could not identify service", attempts=attempts)

    # ── is_ftp_anonymous ──────────────────────────────────────────────────────

    def _answer_is_ftp_anonymous(self, target: str, context: dict) -> Answer:
        attempts = []
        port = context.get("port", 21)

        # Method 1: nmap --script ftp-anon
        self._trying("nmap --script ftp-anon")
        if _tool_exists("nmap"):
            try:
                from agent.core.subprocess_utils import runner
                result = runner.run(
                    ["nmap", "--script", "ftp-anon", "-p", str(port), target],
                    label=f"nmap ftp-anon → {target}",
                    timeout=30,
                )
                if "Anonymous FTP login allowed" in result.raw_output:
                    self._ok("nmap ftp-anon", "anonymous login allowed")
                    return Answer("is_ftp_anonymous", target, True, "nmap ftp-anon",
                                  {"anonymous": True},
                                  attempts=attempts + [Attempt("nmap ftp-anon", True)])
                if "ftp-anon" in result.raw_output:
                    self._ok("nmap ftp-anon", "anonymous login denied")
                    return Answer("is_ftp_anonymous", target, True, "nmap ftp-anon",
                                  {"anonymous": False},
                                  attempts=attempts + [Attempt("nmap ftp-anon", True)])
                attempts.append(Attempt("nmap ftp-anon", False, "inconclusive"))
                self._fail("nmap ftp-anon", "inconclusive output")
            except Exception as e:
                attempts.append(Attempt("nmap ftp-anon", False, str(e)))
                self._fail("nmap ftp-anon", str(e))
        else:
            self._fail("nmap ftp-anon", "not installed")
            attempts.append(Attempt("nmap ftp-anon", False, "not installed"))

        # Method 2: manual ftplib
        self._trying("ftplib anonymous login")
        anon, err = _ftp_anonymous_check(target, int(port))
        if "refused" not in err.lower() and "timed out" not in err.lower():
            self._ok("ftplib", f"anonymous {'allowed' if anon else 'denied'}")
            return Answer("is_ftp_anonymous", target, True, "ftplib",
                          {"anonymous": anon},
                          attempts=attempts + [Attempt("ftplib", True)])
        attempts.append(Attempt("ftplib", False, err))
        self._fail("ftplib", err or "connection failed")

        # Method 3: curl ftp://
        self._trying(f"curl ftp://{target}:{port}/")
        if _tool_exists("curl"):
            try:
                from agent.core.subprocess_utils import run_tool
                _, _, rc = run_tool(
                    ["curl", "--max-time", "5", f"ftp://{target}:{port}/",
                     "--user", "anonymous:test@example.com"],
                    timeout=10,
                )
                anon = rc == 0
                self._ok("curl ftp", f"anonymous {'allowed' if anon else 'denied'}")
                return Answer("is_ftp_anonymous", target, True, "curl_ftp",
                              {"anonymous": anon},
                              attempts=attempts + [Attempt("curl_ftp", True)])
            except Exception as e:
                attempts.append(Attempt("curl_ftp", False, str(e)))
                self._fail("curl ftp", str(e))

        return Answer("is_ftp_anonymous", target, True, "exhausted",
                      {"anonymous": False},
                      error="Could not check FTP anonymous access", attempts=attempts)

    # ── what_web_paths_exist ──────────────────────────────────────────────────

    def _answer_what_web_paths_exist(self, target: str, context: dict) -> Answer:
        attempts = []
        http_target = _ensure_http(target, context.get("port", 80))
        port = context.get("port", 80)
        use_ssl = port in (443, 8443) or context.get("ssl", False)

        # Method 1: webscanner — threaded urllib, no external tool required
        wordlist = context.get("wordlist")
        import re as _re
        clean_target = _re.sub(r'^https?://', '', target).split(':')[0]
        from agent.tools.webscanner import (
            scan as ws_scan, format_for_agent as ws_fmt, build_base_url as _ws_build_url
        )
        display_url = _ws_build_url(clean_target, port)
        self._trying(f"webscanner → {display_url}")
        if not wordlist:
            self._fail("webscanner", "no wordlist provided — skipping web scan")
            attempts.append(Attempt("webscanner", False, "no wordlist"))
        else:
            try:
                ws_found, ws_total = ws_scan(clean_target, port=port, ssl=use_ssl, wordlist=wordlist)
                self._ok("webscanner", f"{len(ws_found)} paths found ({ws_total} scanned)")
                return Answer(
                    "what_web_paths_exist", target, True, "webscanner",
                    {
                        "paths": list(ws_found.keys()),
                        "formatted": ws_fmt(target, ws_found, ws_total),
                    },
                    attempts=attempts + [Attempt("webscanner", True)],
                )
            except Exception as e:
                attempts.append(Attempt("webscanner", False, str(e)))
                self._fail("webscanner", str(e))

        # Method 2: ffuf (external tool)
        self._trying(f"ffuf → {http_target}")
        if _tool_exists("ffuf"):
            try:
                wordlist = _find_wordlist()
                if wordlist:
                    from agent.core.subprocess_utils import runner
                    result = runner.run(
                        ["ffuf", "-u", f"{http_target}/FUZZ", "-w", wordlist,
                         "-mc", "200,301,302,403", "-of", "json",
                         "-o", "/tmp/ffuf_clawstrike.json"],
                        label=f"ffuf → {http_target}",
                        timeout=120,
                    )
                    paths = _parse_ffuf_output("/tmp/ffuf_clawstrike.json")
                    self._ok("ffuf", f"{len(paths)} paths found")
                    return Answer("what_web_paths_exist", target, True, "ffuf",
                                  {"paths": paths},
                                  attempts=attempts + [Attempt("ffuf", True)])
            except Exception as e:
                attempts.append(Attempt("ffuf", False, str(e)))
                self._fail("ffuf", str(e))
        else:
            self._fail("ffuf", "not installed")
            attempts.append(Attempt("ffuf", False, "not installed"))

        # Method 3: dirb
        self._trying(f"dirb {http_target}")
        if _tool_exists("dirb"):
            try:
                from agent.core.subprocess_utils import runner
                result = runner.run(
                    ["dirb", http_target], label=f"dirb → {http_target}", timeout=120,
                )
                paths = _parse_dirb_output(result.clean_output)
                self._ok("dirb", f"{len(paths)} paths found")
                return Answer("what_web_paths_exist", target, True, "dirb",
                              {"paths": paths},
                              attempts=attempts + [Attempt("dirb", True)])
            except Exception as e:
                attempts.append(Attempt("dirb", False, str(e)))
                self._fail("dirb", str(e))
        else:
            self._fail("dirb", "not installed")
            attempts.append(Attempt("dirb", False, "not installed"))

        # Method 4: manual urllib common paths (hardcoded list, no wordlist needed)
        self._trying("manual urllib common paths")
        paths = _manual_path_check(http_target)
        self._ok("manual urllib", f"{len(paths)} paths found")
        return Answer("what_web_paths_exist", target, True, "manual_urllib",
                      {"paths": paths},
                      attempts=attempts + [Attempt("manual_urllib", True)])

    # ── what_web_tech ─────────────────────────────────────────────────────────

    def _answer_what_web_tech(self, target: str, context: dict) -> Answer:
        attempts = []
        http_target = _ensure_http(target, context.get("port", 80))

        # Method 1: whatweb
        self._trying(f"whatweb {http_target}")
        if _tool_exists("whatweb"):
            try:
                from agent.core.subprocess_utils import runner
                result = runner.run(
                    ["whatweb", "-a", "1", http_target],
                    label=f"whatweb → {http_target}",
                    timeout=30,
                )
                tech = _parse_whatweb_output(result.clean_output)
                self._ok("whatweb", f"{len(tech)} technologies detected")
                return Answer("what_web_tech", target, True, "whatweb",
                              {"tech": tech},
                              attempts=attempts + [Attempt("whatweb", True)])
            except Exception as e:
                attempts.append(Attempt("whatweb", False, str(e)))
                self._fail("whatweb", str(e))
        else:
            self._fail("whatweb", "not installed")
            attempts.append(Attempt("whatweb", False, "not installed"))

        # Method 2: curl -I headers
        self._trying("curl -I header analysis")
        if _tool_exists("curl"):
            try:
                from agent.core.subprocess_utils import run_tool
                stdout, _, _ = run_tool(
                    ["curl", "-sI", "--max-time", "10", http_target], timeout=15,
                )
                tech = _parse_headers_for_tech(stdout)
                self._ok("curl headers", f"{len(tech)} technologies detected")
                return Answer("what_web_tech", target, True, "curl_headers",
                              {"tech": tech},
                              attempts=attempts + [Attempt("curl_headers", True)])
            except Exception as e:
                attempts.append(Attempt("curl_headers", False, str(e)))
                self._fail("curl headers", str(e))
        else:
            self._fail("curl headers", "curl not installed")
            attempts.append(Attempt("curl_headers", False, "not installed"))

        # Method 3: nmap http-headers script
        self._trying("nmap --script http-headers")
        if _tool_exists("nmap"):
            try:
                from agent.core.subprocess_utils import runner
                port = context.get("port", 80)
                result = runner.run(
                    ["nmap", "--script", "http-headers", "-p", str(port), target],
                    label=f"nmap http-headers → {target}",
                    timeout=30,
                )
                tech = _parse_nmap_http_headers(result.clean_output)
                self._ok("nmap http-headers", f"{len(tech)} clues found")
                return Answer("what_web_tech", target, True, "nmap http-headers",
                              {"tech": tech},
                              attempts=attempts + [Attempt("nmap http-headers", True)])
            except Exception as e:
                attempts.append(Attempt("nmap http-headers", False, str(e)))
                self._fail("nmap http-headers", str(e))
        else:
            attempts.append(Attempt("nmap http-headers", False, "not installed"))

        # Method 4: urllib manual header inspection
        self._trying("manual urllib header inspection")
        tech = _manual_header_tech(http_target)
        self._ok("manual urllib", f"{len(tech)} clues found")
        return Answer("what_web_tech", target, True, "manual_urllib",
                      {"tech": tech},
                      attempts=attempts + [Attempt("manual_urllib", True)])

    # ── is_web_vulnerable ─────────────────────────────────────────────────────

    def _answer_is_web_vulnerable(self, target: str, context: dict) -> Answer:
        attempts = []
        http_target = _ensure_http(target, context.get("port", 80))

        # Method 1: nikto
        self._trying(f"nikto → {http_target}")
        if _tool_exists("nikto"):
            try:
                from agent.tools.nikto import scan as nikto_scan, format_for_agent
                result = nikto_scan(http_target)
                if not result.error:
                    vulns = [f.description for f in result.findings]
                    self._ok("nikto", f"{len(vulns)} findings")
                    return Answer("is_web_vulnerable", target, True, "nikto",
                                  {"vulnerabilities": vulns, "raw": format_for_agent(result)},
                                  attempts=attempts + [Attempt("nikto", True)])
                attempts.append(Attempt("nikto", False, result.error))
                self._fail("nikto", result.error)
            except Exception as e:
                attempts.append(Attempt("nikto", False, str(e)))
                self._fail("nikto", str(e))
        else:
            self._fail("nikto", "not installed")
            attempts.append(Attempt("nikto", False, "not installed"))

        # Method 2: ZAP active scan
        self._trying(f"zap active scan → {http_target}")
        if _tool_exists("zaproxy") or _tool_exists("zap.sh"):
            try:
                from agent.tools.zap import start_scan as zap_scan, format_for_agent
                result = zap_scan(http_target)
                if not result.error:
                    vulns = [f"{a.risk}: {a.name}" for a in result.alerts]
                    self._ok("zap", f"{len(vulns)} alerts")
                    return Answer("is_web_vulnerable", target, True, "zap",
                                  {"vulnerabilities": vulns, "raw": format_for_agent(result)},
                                  attempts=attempts + [Attempt("zap", True)])
                attempts.append(Attempt("zap", False, result.error))
                self._fail("zap", result.error)
            except Exception as e:
                attempts.append(Attempt("zap", False, str(e)))
                self._fail("zap", str(e))
        else:
            self._fail("zap", "not installed")
            attempts.append(Attempt("zap", False, "not installed"))

        # Method 3: nmap http-vuln scripts
        self._trying("nmap --script http-vuln*")
        if _tool_exists("nmap"):
            try:
                from agent.core.subprocess_utils import runner
                port = context.get("port", 80)
                result = runner.run(
                    ["nmap", "--script", "http-vuln*", "-p", str(port), target],
                    label=f"nmap http-vuln* → {target}",
                    timeout=60,
                )
                vulns = [l.strip() for l in result.clean_output.splitlines()
                         if "VULNERABLE" in l or "CVE" in l]
                self._ok("nmap http-vuln*", f"{len(vulns)} findings")
                return Answer("is_web_vulnerable", target, True, "nmap http-vuln*",
                              {"vulnerabilities": vulns},
                              attempts=attempts + [Attempt("nmap http-vuln*", True)])
            except Exception as e:
                attempts.append(Attempt("nmap http-vuln*", False, str(e)))
                self._fail("nmap http-vuln*", str(e))

        return Answer("is_web_vulnerable", target, False, "exhausted",
                      {"vulnerabilities": []},
                      error="All web vulnerability methods failed", attempts=attempts)

    # ── is_smb_vulnerable ─────────────────────────────────────────────────────

    def _answer_is_smb_vulnerable(self, target: str, context: dict) -> Answer:
        attempts = []

        # Method 1: nmap smb-vuln*
        self._trying("nmap --script smb-vuln*")
        if _tool_exists("nmap"):
            try:
                from agent.core.subprocess_utils import runner
                result = runner.run(
                    ["nmap", "--script", "smb-vuln*", "-p", "445,139", target],
                    label=f"nmap smb-vuln* → {target}",
                    timeout=60,
                )
                vulns = _parse_nmap_smb_vulns(result.clean_output)
                self._ok("nmap smb-vuln*", f"{len(vulns)} findings")
                return Answer("is_smb_vulnerable", target, True, "nmap smb-vuln*",
                              {"vulnerabilities": vulns},
                              attempts=attempts + [Attempt("nmap smb-vuln*", True)])
            except Exception as e:
                attempts.append(Attempt("nmap smb-vuln*", False, str(e)))
                self._fail("nmap smb-vuln*", str(e))
        else:
            self._fail("nmap smb-vuln*", "not installed")
            attempts.append(Attempt("nmap smb-vuln*", False, "not installed"))

        # Method 2: enum4linux-ng
        for binary in ("enum4linux-ng", "enum4linux"):
            self._trying(binary)
            if _tool_exists(binary):
                try:
                    from agent.core.subprocess_utils import runner
                    flag = "-A" if binary == "enum4linux-ng" else "-a"
                    result = runner.run(
                        [binary, flag, target],
                        label=f"{binary} → {target}",
                        timeout=60,
                    )
                    findings = _parse_enum4linux_output(result.clean_output)
                    self._ok(binary, f"{len(findings)} items found")
                    return Answer("is_smb_vulnerable", target, True, binary,
                                  {"vulnerabilities": findings},
                                  attempts=attempts + [Attempt(binary, True)])
                except Exception as e:
                    attempts.append(Attempt(binary, False, str(e)))
                    self._fail(binary, str(e))
            else:
                self._fail(binary, "not installed")
                attempts.append(Attempt(binary, False, "not installed"))

        # Method 4: smbclient -L
        self._trying("smbclient -L")
        if _tool_exists("smbclient"):
            try:
                from agent.core.subprocess_utils import run_tool
                stdout, _, _ = run_tool(
                    ["smbclient", "-L", f"\\\\{target}", "-N"], timeout=15,
                )
                shares = [l.strip() for l in stdout.splitlines()
                          if "Disk" in l or "IPC" in l]
                self._ok("smbclient", f"{len(shares)} shares found")
                return Answer("is_smb_vulnerable", target, True, "smbclient",
                              {"vulnerabilities": shares},
                              attempts=attempts + [Attempt("smbclient", True)])
            except Exception as e:
                attempts.append(Attempt("smbclient", False, str(e)))
                self._fail("smbclient", str(e))

        return Answer("is_smb_vulnerable", target, False, "exhausted",
                      {"vulnerabilities": []},
                      error="All SMB methods failed", attempts=attempts)

    # ── what_ssh_ciphers ──────────────────────────────────────────────────────

    def _answer_what_ssh_ciphers(self, target: str, context: dict) -> Answer:
        attempts = []
        port = context.get("port", 22)

        # Method 1: ssh-audit
        self._trying("ssh-audit")
        if _tool_exists("ssh-audit"):
            try:
                from agent.core.subprocess_utils import runner
                result = runner.run(
                    ["ssh-audit", f"{target}:{port}"],
                    label=f"ssh-audit → {target}:{port}",
                    timeout=30,
                )
                weak = _parse_ssh_audit_weak(result.clean_output)
                self._ok("ssh-audit", f"{len(weak)} weak ciphers found")
                return Answer("what_ssh_ciphers", target, True, "ssh-audit",
                              {"weak_ciphers": weak, "raw": result.clean_output},
                              attempts=attempts + [Attempt("ssh-audit", True)])
            except Exception as e:
                attempts.append(Attempt("ssh-audit", False, str(e)))
                self._fail("ssh-audit", str(e))
        else:
            self._fail("ssh-audit", "not installed")
            attempts.append(Attempt("ssh-audit", False, "not installed"))

        # Method 2: nmap ssh2-enum-algos
        self._trying("nmap --script ssh2-enum-algos")
        if _tool_exists("nmap"):
            try:
                from agent.core.subprocess_utils import runner
                result = runner.run(
                    ["nmap", "--script", "ssh2-enum-algos", "-p", str(port), target],
                    label=f"nmap ssh2-enum-algos → {target}",
                    timeout=30,
                )
                weak = _parse_nmap_ssh_algos(result.clean_output)
                self._ok("nmap ssh2-enum-algos", f"{len(weak)} weak algos found")
                return Answer("what_ssh_ciphers", target, True, "nmap ssh2-enum-algos",
                              {"weak_ciphers": weak},
                              attempts=attempts + [Attempt("nmap ssh2-enum-algos", True)])
            except Exception as e:
                attempts.append(Attempt("nmap ssh2-enum-algos", False, str(e)))
                self._fail("nmap ssh2-enum-algos", str(e))
        else:
            attempts.append(Attempt("nmap ssh2-enum-algos", False, "not installed"))

        # Method 3: SSH banner grab
        self._trying(f"ssh banner grab :{port}")
        banner, err = _banner_grab(target, int(port), timeout=3)
        if banner and "SSH" in banner:
            self._ok("banner grab", banner.strip()[:60])
            return Answer("what_ssh_ciphers", target, True, "banner_grab",
                          {"weak_ciphers": [], "banner": banner},
                          attempts=attempts + [Attempt("banner_grab", True)])
        attempts.append(Attempt("banner_grab", False, err or "no SSH banner"))
        self._fail("banner grab", err or "no SSH banner")

        return Answer("what_ssh_ciphers", target, False, "exhausted",
                      {"weak_ciphers": []},
                      error="Could not enumerate SSH ciphers", attempts=attempts)

    # ── is_db_default_creds ───────────────────────────────────────────────────

    def _answer_is_db_default_creds(self, target: str, context: dict) -> Answer:
        attempts = []
        service = context.get("service", "mysql")
        port = context.get("port", 3306)

        script_map = {
            "mysql": ("mysql-empty-password", 3306),
            "postgresql": ("pgsql-brute", 5432),
            "mssql": ("ms-sql-empty-password", 1433),
        }
        script, _ = script_map.get(service, (None, port))

        # Method 1: nmap script
        if script and _tool_exists("nmap"):
            self._trying(f"nmap --script {script}")
            try:
                from agent.core.subprocess_utils import runner
                result = runner.run(
                    ["nmap", "--script", script, "-p", str(port), target],
                    label=f"nmap {script} → {target}",
                    timeout=30,
                )
                raw = result.raw_output
                if "empty password" in raw.lower() or "Login correct" in raw:
                    self._ok(f"nmap {script}", "default/empty credentials work")
                    return Answer("is_db_default_creds", target, True, f"nmap {script}",
                                  {"vulnerable": True, "creds": "empty/default"},
                                  attempts=attempts + [Attempt(f"nmap {script}", True)])
                if script in raw:
                    self._ok(f"nmap {script}", "no default credentials")
                    return Answer("is_db_default_creds", target, True, f"nmap {script}",
                                  {"vulnerable": False, "creds": ""},
                                  attempts=attempts + [Attempt(f"nmap {script}", True)])
                attempts.append(Attempt(f"nmap {script}", False, "inconclusive"))
                self._fail(f"nmap {script}", "inconclusive")
            except Exception as e:
                attempts.append(Attempt(f"nmap {script}", False, str(e)))
                self._fail(f"nmap {script}", str(e))

        # Method 2: manual connection
        self._trying(f"manual {service} default creds probe")
        vuln, creds, err = _db_default_creds_check(target, int(port), service)
        if not err:
            self._ok(f"manual {service}", f"creds: {creds}" if vuln else "not vulnerable")
            return Answer("is_db_default_creds", target, True, f"manual_{service}",
                          {"vulnerable": vuln, "creds": creds},
                          attempts=attempts + [Attempt(f"manual_{service}", True)])
        attempts.append(Attempt(f"manual_{service}", False, err))
        self._fail(f"manual {service}", err)

        return Answer("is_db_default_creds", target, False, "exhausted",
                      {"vulnerable": False, "creds": ""},
                      error="Could not check DB default credentials", attempts=attempts)

    # ── what_cves_apply ───────────────────────────────────────────────────────

    def _answer_what_cves_apply(self, target: str, context: dict) -> Answer:
        services = context.get("services", {})
        router = context.get("router")
        phase3_summary = context.get("phase3_summary", "")

        service_lines = "\n".join(
            f"  Port {port}: {info.get('service','')} {info.get('version','')}"
            for port, info in services.items()
        )
        prompt = (
            f"Target: {target}\nServices:\n{service_lines}\n\n"
            f"Enumeration findings:\n{phase3_summary}\n\n"
            "List exploitable CVEs in order of severity. "
            "Include: CVE ID, affected service/version, severity, description, "
            "whether a Metasploit module likely exists."
        )

        self._trying("AI CVE analysis (smart model)")
        try:
            if router:
                analysis = router.chat(
                    "analyze",
                    system="You are an expert penetration tester performing authorized security assessments.",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=2048,
                )
            else:
                analysis = "No AI router available for CVE analysis."
            self._ok("AI CVE analysis", "complete")
            return Answer("what_cves_apply", target, True, "ai_analysis",
                          {"analysis": analysis})
        except Exception as e:
            self._fail("AI CVE analysis", str(e))
            return Answer("what_cves_apply", target, False, "ai_analysis", error=str(e))

    # ── what_exploits_available ───────────────────────────────────────────────

    def _answer_what_exploits_available(self, target: str, context: dict) -> Answer:
        services = context.get("services", {})
        cve_analysis = context.get("cve_analysis", "")
        router = context.get("router")

        service_lines = "\n".join(
            f"  Port {port}: {info.get('service','')} {info.get('version','')}"
            for port, info in services.items()
        )
        prompt = (
            f"Target: {target}\nServices:\n{service_lines}\n\n"
            f"CVE Analysis:\n{cve_analysis}\n\n"
            "Produce a ranked exploitation plan. Write the full human-readable plan first.\n\n"
            "Then append this JSON block at the very end (required for automated exploit commands):\n\n"
            "[EXPLOIT_OPTIONS_JSON]\n"
            "[\n"
            '  {"n": 1, "title": "Short title", "module": "exploit/path/or/empty_string", '
            '"payload": "payload/path/or/empty_string", "notes": "one line summary", "risk": "HIGH"},\n'
            "  ...\n"
            "]\n"
            "[/EXPLOIT_OPTIONS_JSON]\n\n"
            "JSON rules: module = exact Metasploit module path, or empty string if none. "
            "payload = recommended payload path, or empty string. "
            "risk = HIGH, MEDIUM, or LOW."
        )

        self._trying("AI exploit planner (smart model)")
        try:
            if router:
                raw = router.chat(
                    "exploit",
                    system="You are an expert penetration tester performing authorized security assessments.",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=2048,
                )
            else:
                raw = "No AI router available for exploitation planning."
            plan, exploit_options = _parse_exploit_plan(raw)
            self._ok("AI exploit planner", f"{len(exploit_options)} option(s) parsed")
            return Answer("what_exploits_available", target, True, "ai_planner",
                          {"plan": plan, "exploit_options": exploit_options})
        except Exception as e:
            self._fail("AI exploit planner", str(e))
            return Answer("what_exploits_available", target, False, "ai_planner", error=str(e))


# ── Module-level singleton ────────────────────────────────────────────────────
intelligence = PentestIntelligence()


# ── Low-level helpers ─────────────────────────────────────────────────────────

def _tool_exists(name: str) -> bool:
    from agent.core.subprocess_utils import tool_exists
    return tool_exists(name)


def _tcp_probe(host: str, port: int, timeout: float = 2) -> tuple:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True, ""
    except ConnectionRefusedError:
        return False, "connection refused"
    except OSError as e:
        return False, str(e)


def _banner_grab(host: str, port: int, timeout: float = 3) -> tuple:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode("utf-8", errors="replace")
        s.close()
        return banner, ""
    except Exception as e:
        return "", str(e)


def _socket_sweep(host: str, ports: list, timeout: float = 1) -> list:
    return [p for p in ports if _tcp_probe(host, p, timeout)[0]]


def _ftp_anonymous_check(host: str, port: int) -> tuple:
    try:
        import ftplib
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=5)
        ftp.login("anonymous", "test@example.com")
        ftp.quit()
        return True, ""
    except Exception as e:
        return False, str(e)


def _db_default_creds_check(host: str, port: int, service: str) -> tuple:
    if service == "mysql":
        try:
            import subprocess
            r = subprocess.run(
                ["mysql", "-h", host, "-P", str(port), "-u", "root", "--password=",
                 "-e", "SELECT 1", "--connect-timeout=3"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            )
            return r.returncode == 0, "root:(empty)" if r.returncode == 0 else "", ""
        except FileNotFoundError:
            return False, "", "mysql client not installed"
        except Exception as e:
            return False, "", str(e)
    return False, "", f"manual check not implemented for {service}"


def _extract_ports(hosts) -> list:
    ports = []
    for host in hosts:
        for p in host.ports:
            try:
                ports.append(int(p["port"]))
            except (KeyError, ValueError):
                pass
    return sorted(set(ports))


def _parse_masscan_ports(output: str) -> list:
    import re
    ports = []
    for line in output.splitlines():
        m = re.search(r"port (\d+)/", line)
        if m:
            ports.append(int(m.group(1)))
    return sorted(set(ports))


def _parse_ffuf_output(json_path: str) -> list:
    import json
    from pathlib import Path
    try:
        data = json.loads(Path(json_path).read_text())
        return [r["input"]["FUZZ"] for r in data.get("results", [])]
    except Exception:
        return []


def _parse_dirb_output(output: str) -> list:
    import re
    paths = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("+ ") and "CODE:" in line:
            m = re.search(r"https?://[^/]+(/[^\s]+)", line)
            if m:
                paths.append(m.group(1))
    return paths


def _parse_whatweb_output(output: str) -> list:
    import re
    tech = []
    for line in output.splitlines():
        if "[" in line:
            for item in re.findall(r"\[([^\]]+)\]", line):
                item = item.split("/")[0].strip()
                if item and item not in tech:
                    tech.append(item)
    return tech


def _parse_headers_for_tech(headers: str) -> list:
    tech = []
    for line in headers.lower().splitlines():
        for header in ("server:", "x-powered-by:", "x-generator:"):
            if line.startswith(header):
                val = line.split(":", 1)[1].strip()
                if val and val not in tech:
                    tech.append(val)
    return tech


def _parse_nmap_http_headers(output: str) -> list:
    tech = []
    for line in output.splitlines():
        line = line.strip()
        if "Server:" in line or "X-Powered-By:" in line:
            val = line.split(":", 1)[-1].strip()
            if val and val not in tech:
                tech.append(val)
    return tech


def _manual_header_tech(url: str) -> list:
    try:
        import urllib.request
        req = urllib.request.urlopen(url, timeout=5)
        tech = []
        for h in ("Server", "X-Powered-By", "X-Generator"):
            val = req.headers.get(h)
            if val and val not in tech:
                tech.append(val)
        return tech
    except Exception:
        return []


def _parse_nmap_smb_vulns(output: str) -> list:
    return [l.strip() for l in output.splitlines()
            if "VULNERABLE" in l or "CVE" in l]


def _parse_enum4linux_output(output: str) -> list:
    findings = [l.strip() for l in output.splitlines()
                if l.strip().startswith("[+]")]
    return findings[:30]


def _parse_ssh_audit_weak(output: str) -> list:
    return [l.strip() for l in output.splitlines()
            if "-- [fail]" in l or "-- [warn]" in l]


def _parse_nmap_ssh_algos(output: str) -> list:
    weak_keywords = ["arcfour", "des", "md5", "sha1",
                     "diffie-hellman-group1", "diffie-hellman-group14"]
    weak = []
    for line in output.splitlines():
        ll = line.lower().strip()
        if any(kw in ll for kw in weak_keywords) and line.strip() not in weak:
            weak.append(line.strip())
    return weak


def _guess_service_from_banner(banner: str, port: int) -> tuple:
    bl = banner.lower()
    if "ssh" in bl:
        parts = banner.strip().split()
        return "ssh", (parts[1] if len(parts) > 1 else "")
    if "ftp" in bl or "220 " in banner:
        return "ftp", banner.split("\n")[0].strip()[:50]
    if "smtp" in bl:
        return "smtp", banner.split("\n")[0].strip()[:50]
    if "http" in bl or "html" in bl:
        return "http", _extract_server_header(banner)
    defaults = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
                80: "http", 443: "https", 3306: "mysql",
                5432: "postgresql", 3389: "rdp", 5900: "vnc"}
    return defaults.get(port, "unknown"), ""


def _extract_server_header(headers: str) -> str:
    for line in headers.splitlines():
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()
    return ""


def _ensure_http(target: str, port: int = 80) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    scheme = "https" if port in (443, 8443) else "http"
    return f"{scheme}://{target}:{port}"


def _find_wordlist() -> Optional[str]:
    from pathlib import Path
    for candidate in [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/dirb/wordlists/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ]:
        if Path(candidate).exists():
            return candidate
    return None


def _parse_exploit_plan(text: str) -> tuple:
    """Split AI plan text into (human_readable, structured_options_list).

    Looks for [EXPLOIT_OPTIONS_JSON]...[/EXPLOIT_OPTIONS_JSON] block.
    Returns the text before it and the parsed list (empty list on failure).
    """
    import re, json
    m = re.search(r"\[EXPLOIT_OPTIONS_JSON\](.*?)\[/EXPLOIT_OPTIONS_JSON\]",
                  text, re.DOTALL)
    if not m:
        return text.strip(), []
    clean = text[: m.start()].strip()
    try:
        options = json.loads(m.group(1).strip())
        if not isinstance(options, list):
            return clean, []
        return clean, options
    except (json.JSONDecodeError, ValueError):
        return clean, []


_COMMON_PATHS = [
    "/admin", "/login", "/wp-admin", "/wp-login.php", "/administrator",
    "/phpmyadmin", "/manager", "/console", "/api", "/api/v1", "/backup",
    "/config", "/dashboard", "/upload", "/uploads", "/files",
    "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env", "/server-status",
]


def _manual_path_check(base_url: str) -> list:
    import urllib.request
    found = []
    for path in _COMMON_PATHS:
        try:
            url = base_url.rstrip("/") + path
            req = urllib.request.urlopen(url, timeout=3)
            if req.status in (200, 301, 302, 403):
                found.append(f"{path}  (Status: {req.status})")
        except Exception:
            pass
    return found
