import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from rich.console import Console

console = Console()

ZAP_PORT = 8090
ZAP_API_KEY = "clawstrike"
ZAP_PROXY = f"http://localhost:{ZAP_PORT}"

# Ordered list of well-known ZAP binary locations (config.yaml takes priority)
_ZAP_KNOWN_PATHS = [
    "/Applications/ZAP.app/Contents/Java/zap.sh",  # macOS homebrew cask
    "/usr/share/zaproxy/zap.sh",                    # Debian/Ubuntu apt
    "/opt/zaproxy/zap.sh",                          # manual Linux install
]


def _resolve_zap_bin() -> Optional[str]:
    """
    Return the first usable ZAP binary path, trying in order:
      1. tools.zap_path in config.yaml
      2. Known fixed paths (macOS cask, Debian apt, manual Linux)
      3. zap.sh / zaproxy on PATH via shutil.which
    Returns None if nothing is found.
    """
    # 1. config.yaml override
    try:
        import yaml
        cfg_path = Path(__file__).resolve().parents[2] / "config.yaml"
        cfg = yaml.safe_load(cfg_path.read_text())
        zap_path = cfg.get("tools", {}).get("zap_path", "")
        if zap_path and Path(zap_path).is_file():
            return zap_path
    except Exception:
        pass

    # 2. known fixed paths
    for candidate in _ZAP_KNOWN_PATHS:
        if Path(candidate).is_file():
            return candidate

    # 3. PATH
    return shutil.which("zap.sh") or shutil.which("zaproxy")


@dataclass
class ZAPAlert:
    risk: str
    name: str
    url: str
    description: str
    solution: str


@dataclass
class ZAPResult:
    target: str
    alerts: list = field(default_factory=list)
    urls_found: list = field(default_factory=list)
    error: Optional[str] = None


def _is_zap_up() -> bool:
    sock = socket.socket()
    sock.settimeout(1)
    try:
        sock.connect(("localhost", ZAP_PORT))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _ensure_zap_running() -> Optional[str]:
    if _is_zap_up():
        return None

    zap_bin = _resolve_zap_bin()

    if zap_bin is None:
        from agent.core.tools_registry import REGISTRY
        _t = REGISTRY["zaproxy"]
        tried = "\n".join(f"  {p}" for p in _ZAP_KNOWN_PATHS)
        return (
            f"zaproxy not installed. Run: {_t.apt}\n\n"
            "Searched paths:\n"
            f"{tried}\n"
            "  zap.sh / zaproxy on PATH\n\n"
            "Or start ZAP manually and set tools.zap_path in config.yaml."
        )

    try:
        subprocess.Popen(
            [zap_bin, "-daemon", "-port", str(ZAP_PORT),
             "-config", f"api.key={ZAP_API_KEY}",
             "-config", "api.addrs.addr.name=.*",
             "-config", "api.addrs.addr.regex=true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        console.print(f"[dim]ZAP daemon starting ({zap_bin}) on port {ZAP_PORT}…[/dim]")
        for _ in range(30):
            time.sleep(1)
            if _is_zap_up():
                console.print("[dim green]ZAP daemon ready[/dim green]")
                return None
        return f"ZAP started via {zap_bin} but did not respond within 30 seconds"
    except FileNotFoundError:
        return f"ZAP binary not executable: {zap_bin}"


def _get_client():
    try:
        from zapv2 import ZAPv2
        return ZAPv2(
            apikey=ZAP_API_KEY,
            proxies={"http": ZAP_PROXY, "https": ZAP_PROXY},
        )
    except ImportError:
        raise ImportError(
            "python-owasp-zap-v2.4 not installed — run:\n"
            "  pip install python-owasp-zap-v2.4"
        )


def spider(target: str) -> ZAPResult:
    err = _ensure_zap_running()
    if err:
        return ZAPResult(target=target, error=err)

    try:
        zap = _get_client()
        console.print(f"[dim]ZAP spider: {target}[/dim]")
        scan_id = zap.spider.scan(target, apikey=ZAP_API_KEY)
        while int(zap.spider.status(scan_id)) < 100:
            time.sleep(2)
        urls = zap.spider.results(scan_id)
        console.print(f"[dim]ZAP spider complete — {len(urls)} URL(s) found[/dim]")
        return ZAPResult(target=target, urls_found=list(urls))
    except ImportError as e:
        return ZAPResult(target=target, error=str(e))
    except Exception as e:
        return ZAPResult(target=target, error=f"ZAP spider failed: {e}")


def get_alerts(target: str) -> list:
    try:
        zap = _get_client()
        return zap.core.alerts(baseurl=target, apikey=ZAP_API_KEY) or []
    except Exception:
        return []


def start_scan(target: str) -> ZAPResult:
    err = _ensure_zap_running()
    if err:
        return ZAPResult(target=target, error=err)

    try:
        zap = _get_client()

        # Spider phase
        console.print(f"[dim]ZAP spider: {target}[/dim]")
        spider_id = zap.spider.scan(target, apikey=ZAP_API_KEY)
        while int(zap.spider.status(spider_id)) < 100:
            time.sleep(2)
        urls = list(zap.spider.results(spider_id))
        console.print(f"[dim]ZAP spider complete — {len(urls)} URL(s)[/dim]")

        # Active scan phase
        console.print(f"[dim]ZAP active scan: {target}[/dim]")
        scan_id = zap.ascan.scan(target, apikey=ZAP_API_KEY)
        while int(zap.ascan.status(scan_id)) < 100:
            time.sleep(5)
        console.print("[dim]ZAP active scan complete[/dim]")

        raw_alerts = zap.core.alerts(baseurl=target, apikey=ZAP_API_KEY) or []
        alerts = [
            ZAPAlert(
                risk=a.get("risk", "Unknown"),
                name=a.get("alert", ""),
                url=a.get("url", ""),
                description=a.get("description", ""),
                solution=a.get("solution", ""),
            )
            for a in raw_alerts
        ]

        return ZAPResult(target=target, alerts=alerts, urls_found=urls)

    except ImportError as e:
        return ZAPResult(target=target, error=str(e))
    except Exception as e:
        return ZAPResult(target=target, error=f"ZAP scan failed: {e}")


def format_for_agent(result: ZAPResult) -> str:
    if result.error:
        return f"ZAP ERROR: {result.error}"

    lines = [f"ZAP scan complete on {result.target}."]

    if result.urls_found:
        lines.append(f"Spider crawled {len(result.urls_found)} URL(s).")

    if not result.alerts:
        lines.append("No alerts found.")
        return "\n".join(lines)

    by_risk: dict[str, list] = {}
    for alert in result.alerts:
        by_risk.setdefault(alert.risk, []).append(alert)

    lines.append(f"\nFound {len(result.alerts)} alert(s):\n")
    for risk in ("High", "Medium", "Low", "Informational"):
        if risk not in by_risk:
            continue
        lines.append(f"[{risk.upper()}]")
        for a in by_risk[risk]:
            lines.append(f"  • {a.name}")
            lines.append(f"    URL: {a.url}")
            if a.solution:
                lines.append(f"    Fix: {a.solution[:150].strip()}")
        lines.append("")

    return "\n".join(lines)
