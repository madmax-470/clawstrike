import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console

console = Console()

ZAP_PORT = 8090
ZAP_API_KEY = "clawstrike"
ZAP_PROXY = f"http://localhost:{ZAP_PORT}"

_ZAP_BINS = [
    "zap.sh",
    "/usr/share/zaproxy/zap.sh",
    "zaproxy",
    "/opt/zaproxy/zap.sh",
]


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

    for zap_bin in _ZAP_BINS:
        try:
            subprocess.Popen(
                [zap_bin, "-daemon", "-port", str(ZAP_PORT),
                 "-config", f"api.key={ZAP_API_KEY}",
                 "-config", "api.addrs.addr.name=.*",
                 "-config", "api.addrs.addr.regex=true"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            console.print(f"[dim]ZAP daemon starting on port {ZAP_PORT}…[/dim]")
            for _ in range(30):
                time.sleep(1)
                if _is_zap_up():
                    console.print("[dim green]ZAP daemon ready[/dim green]")
                    return None
            return f"ZAP started via {zap_bin} but did not respond within 30 seconds"
        except FileNotFoundError:
            continue

    return (
        "ZAP not found — install with:\n"
        "  sudo apt install zaproxy\n"
        "Or start it manually first:\n"
        f"  zap.sh -daemon -port {ZAP_PORT} -config api.key={ZAP_API_KEY}"
    )


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
