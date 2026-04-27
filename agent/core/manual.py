"""
Pure stdlib fallback implementations — used automatically when external
pentest tool binaries are unavailable. Zero third-party imports.
"""

import html
import re
import socket
import ssl
import urllib.error
import urllib.request
from typing import Optional

CONNECT_TIMEOUT = 1.0
BANNER_TIMEOUT = 2.0

COMMON_PORTS = {
    21: "ftp",    22: "ssh",     23: "telnet",  25: "smtp",
    53: "dns",    80: "http",   110: "pop3",   111: "rpcbind",
    135: "msrpc", 139: "netbios", 143: "imap",  443: "https",
    445: "smb",   993: "imaps",  995: "pop3s", 1433: "mssql",
    1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc",  6379: "redis", 8080: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9200: "elasticsearch", 27017: "mongodb",
}

COMMON_PATHS = [
    "/admin", "/login", "/wp-admin", "/phpmyadmin", "/dashboard",
    "/api", "/api/v1", "/api/v2", "/swagger", "/swagger-ui.html",
    "/.env", "/.git/HEAD", "/robots.txt", "/sitemap.xml",
    "/backup", "/config", "/uploads", "/static", "/assets",
    "/admin/login", "/user/login", "/manager", "/console",
    "/server-status", "/server-info", "/.well-known/security.txt",
]

_INTERESTING_HEADERS = (
    "x-powered-by", "x-aspnet-version", "x-generator",
    "x-frame-options", "strict-transport-security",
    "content-security-policy", "set-cookie",
)


def _strip_scheme(target: str) -> str:
    host = target
    for prefix in ("https://", "http://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
            break
    return host.split("/")[0].split(":")[0]


def _quick_banner(host: str, port: int) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(BANNER_TIMEOUT)
    try:
        sock.connect((host, port))
        sock.sendall(b"\r\n")
        return sock.recv(64).decode("utf-8", errors="replace").strip()
    except OSError:
        return ""
    finally:
        sock.close()


# ─── port_scan ────────────────────────────────────────────────────────────────

def port_scan(target: str, ports: Optional[list] = None) -> dict:
    """Raw socket connect scan over common ports. Fallback for nmap."""
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    host = _strip_scheme(target)
    open_ports = []

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        try:
            if sock.connect_ex((host, port)) == 0:
                banner = ""
                try:
                    banner = _quick_banner(host, port)
                except Exception:
                    pass
                open_ports.append({
                    "port": str(port),
                    "protocol": "tcp",
                    "service": COMMON_PORTS.get(port, "unknown"),
                    "version": banner[:60],
                })
        except OSError:
            pass
        finally:
            sock.close()

    return {
        "host": host,
        "target": target,
        "open_ports": open_ports,
        "method": "manual socket scan (nmap not available)",
    }


# ─── banner_grab ──────────────────────────────────────────────────────────────

def banner_grab(target: str, port: int) -> dict:
    """Connect to target:port, send \\r\\n probe, return service banner."""
    host = _strip_scheme(target)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(BANNER_TIMEOUT)
    try:
        sock.connect((host, port))
        sock.sendall(b"\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        return {"host": host, "port": port, "banner": banner, "error": None}
    except socket.timeout:
        return {"host": host, "port": port, "banner": "", "error": "timed out"}
    except OSError as e:
        return {"host": host, "port": port, "banner": "", "error": str(e)}
    finally:
        sock.close()


# ─── http_fingerprint ─────────────────────────────────────────────────────────

def http_fingerprint(target: str) -> dict:
    """urllib HTTP inspection: status, server, headers, title, redirects. Fallback for nikto."""
    if not target.startswith("http://") and not target.startswith("https://"):
        target = f"http://{target}"

    result = {
        "target": target,
        "status_code": None,
        "server": "",
        "headers": {},
        "title": "",
        "redirect_chain": [],
        "interesting": [],
        "error": None,
        "method": "manual urllib fingerprint (nikto not available)",
    }

    redirect_chain: list = []

    class _RedirectRecorder(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            redirect_chain.append({"code": code, "url": newurl})
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(_RedirectRecorder)
    req = urllib.request.Request(
        target,
        headers={"User-Agent": "Mozilla/5.0 (compatible; ClawStrike/0.1)", "Accept": "*/*"},
    )

    try:
        with opener.open(req, timeout=10) as resp:
            result["status_code"] = resp.status
            headers = dict(resp.headers)
            result["headers"] = headers
            result["server"] = headers.get("Server", headers.get("server", ""))
            result["redirect_chain"] = redirect_chain

            body = resp.read(8192).decode("utf-8", errors="replace")
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
            if m:
                result["title"] = html.unescape(m.group(1).strip())[:120]

            for k in _INTERESTING_HEADERS:
                val = headers.get(k, headers.get(k.title(), ""))
                if val:
                    result["interesting"].append(f"{k}: {val[:100]}")

    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        result["error"] = f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        result["error"] = f"Connection failed: {e.reason}"
    except Exception as e:
        result["error"] = str(e)

    return result


# ─── probe_common_paths ───────────────────────────────────────────────────────

def probe_common_paths(target: str) -> list:
    """
    Probe COMMON_PATHS with urllib. Returns list of gobuster-style result strings.
    Fallback for gobuster when binary is unavailable.
    """
    if not target.startswith("http://") and not target.startswith("https://"):
        target = f"http://{target}"

    found = []
    for path in COMMON_PATHS:
        url = target.rstrip("/") + path
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ClawStrike/0.1)"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                size = len(resp.read(4096))
                found.append(f"{path} (Status: {resp.status}) [Size: ~{size}]")
        except urllib.error.HTTPError as e:
            if e.code not in (404, 400):
                found.append(f"{path} (Status: {e.code})")
        except Exception:
            pass

    return found


# ─── dns_enum ─────────────────────────────────────────────────────────────────

def dns_enum(target: str) -> dict:
    """A/AAAA records + reverse PTR via socket. Fallback when dig/nslookup unavailable."""
    host = _strip_scheme(target)
    result = {
        "target": host,
        "a_records": [],
        "aaaa_records": [],
        "ptr_records": [],
        "canonical": "",
        "error": None,
        "method": "manual socket DNS (dig not available)",
    }

    try:
        name, _aliases, addresses = socket.gethostbyname_ex(host)
        result["canonical"] = name
        result["a_records"] = addresses
    except socket.gaierror as e:
        result["error"] = f"DNS lookup failed: {e}"
        return result

    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET6)
        result["aaaa_records"] = list({info[4][0] for info in infos})
    except socket.gaierror:
        pass

    for ip in result["a_records"]:
        try:
            ptr = socket.gethostbyaddr(ip)[0]
            result["ptr_records"].append({"ip": ip, "ptr": ptr})
        except socket.herror:
            result["ptr_records"].append({"ip": ip, "ptr": ""})

    return result


# ─── ssl_inspect ──────────────────────────────────────────────────────────────

def ssl_inspect(target: str) -> dict:
    """Pull TLS certificate: subject, issuer, SANs, validity via ssl module."""
    host = _strip_scheme(target)
    result = {
        "target": host,
        "subject": {},
        "issuer": {},
        "san": [],
        "not_before": "",
        "not_after": "",
        "version": "",
        "error": None,
        "method": "manual ssl module",
    }

    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(
            socket.create_connection((host, 443), timeout=5),
            server_hostname=host,
        ) as tls:
            cert = tls.getpeercert()

        result["subject"] = dict(x[0] for x in cert.get("subject", []))
        result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
        result["not_before"] = cert.get("notBefore", "")
        result["not_after"] = cert.get("notAfter", "")
        result["version"] = str(cert.get("version", ""))
        result["san"] = [
            value
            for kind, value in cert.get("subjectAltName", [])
            if kind == "DNS"
        ]
    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificate verification failed: {e}"
    except ConnectionRefusedError:
        result["error"] = f"Port 443 not open on {host}"
    except OSError as e:
        result["error"] = str(e)

    return result


# ─── Formatters ───────────────────────────────────────────────────────────────

def format_port_scan(r: dict) -> str:
    lines = [f"Manual port scan of {r['host']} [{r['method']}].\n"]
    if not r["open_ports"]:
        lines.append("No open ports found in common port range.")
        return "\n".join(lines)
    lines.append(f"Open ports ({len(r['open_ports'])}):")
    for p in r["open_ports"]:
        ver = f" — {p['version']}" if p["version"] else ""
        lines.append(f"  {p['port']}/tcp  {p['service']}{ver}")
    return "\n".join(lines)


def format_http_fingerprint(r: dict) -> str:
    if r["error"] and not r["status_code"]:
        return f"Manual HTTP fingerprint of {r['target']}: {r['error']}"
    lines = [
        f"Manual HTTP fingerprint of {r['target']} [{r['method']}].",
        f"  Status : {r['status_code']}",
        f"  Server : {r['server'] or '(not disclosed)'}",
        f"  Title  : {r['title'] or '(none)'}",
    ]
    if r["redirect_chain"]:
        lines.append("  Redirects:")
        for rd in r["redirect_chain"]:
            lines.append(f"    {rd['code']} → {rd['url']}")
    if r["interesting"]:
        lines.append("  Notable headers:")
        for h in r["interesting"]:
            lines.append(f"    {h}")
    return "\n".join(lines)


def format_dns_enum(r: dict) -> str:
    if r["error"]:
        return f"Manual DNS enum of {r['target']}: {r['error']}"
    lines = [f"Manual DNS enum of {r['target']} [{r['method']}]."]
    if r["a_records"]:
        lines.append(f"  A    : {', '.join(r['a_records'])}")
    if r["aaaa_records"]:
        lines.append(f"  AAAA : {', '.join(r['aaaa_records'])}")
    if r["canonical"] and r["canonical"] != r["target"]:
        lines.append(f"  CNAME: {r['canonical']}")
    for ptr in r["ptr_records"]:
        if ptr["ptr"]:
            lines.append(f"  PTR  {ptr['ip']}: {ptr['ptr']}")
    return "\n".join(lines)


def format_ssl_inspect(r: dict) -> str:
    if r["error"]:
        return f"Manual SSL inspect of {r['target']}: {r['error']}"
    lines = [f"Manual SSL inspect of {r['target']}."]
    cn = r["subject"].get("commonName", "")
    if cn:
        lines.append(f"  Subject CN : {cn}")
    issuer_o = r["issuer"].get("organizationName", "")
    if issuer_o:
        lines.append(f"  Issued by  : {issuer_o}")
    lines.append(f"  Valid from : {r['not_before']}")
    lines.append(f"  Expires    : {r['not_after']}")
    if r["san"]:
        lines.append(f"  SANs ({len(r['san'])}): {', '.join(r['san'][:8])}")
        if len(r["san"]) > 8:
            lines.append(f"    … and {len(r['san']) - 8} more")
    return "\n".join(lines)
