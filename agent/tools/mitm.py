import os
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from rich.console import Console
from agent.core.subprocess_utils import run_tool, tool_exists, get_env

console = Console()

CAPTURE_DURATION = 60
_FLOWS_BASE = Path("engagements")

_proxy_process = None


@dataclass
class CapturedRequest:
    method: str
    url: str
    status_code: Optional[int]
    request_headers: dict
    response_headers: dict
    content_type: str


@dataclass
class MitmResult:
    target: str
    requests: list = field(default_factory=list)
    flows_file: Optional[str] = None
    error: Optional[str] = None


def _flows_path(target: str) -> Path:
    safe = target.replace("://", "_").replace("/", "_").replace(":", "_")
    path = _FLOWS_BASE / safe / "mitm"
    path.mkdir(parents=True, exist_ok=True)
    return path / "capture.flows"


def _extract_host(target: str) -> str:
    host = target
    for prefix in ("https://", "http://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
            break
    return host.split("/")[0].split(":")[0]


def capture_traffic(target: str, port: int = 8080, duration: int = CAPTURE_DURATION) -> MitmResult:
    """Run mitmdump for `duration` seconds, capturing traffic from `target`."""
    if not tool_exists("mitmdump"):
        from agent.core.tools_registry import REGISTRY
        _t = REGISTRY["mitmproxy"]
        return MitmResult(
            target=target,
            error=f"mitmproxy not installed. Run: {_t.apt}",
        )

    host = _extract_host(target)
    flows_file = _flows_path(target)

    console.print(
        f"[dim]mitmdump: capturing {host} for {duration}s "
        f"on :{port} → {flows_file}[/dim]"
    )

    import subprocess
    env = get_env()
    import shutil
    binary = shutil.which("mitmdump", path=env["PATH"]) or "mitmdump"

    try:
        proc = subprocess.Popen(
            [
                binary,
                "--listen-port", str(port),
                "--flow-detail", "0",
                "-w", str(flows_file),
                f"~d {host}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=env,
        )

        time.sleep(duration)

        try:
            os.kill(proc.pid, signal.SIGTERM)
            proc.wait(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            proc.kill()

        if not flows_file.exists() or flows_file.stat().st_size == 0:
            return MitmResult(
                target=target,
                error=(
                    f"No traffic captured for {host}.\n"
                    f"Route your traffic through the proxy first:\n"
                    f"  export http_proxy=http://127.0.0.1:{port}\n"
                    f"  export https_proxy=http://127.0.0.1:{port}"
                ),
            )

        return get_captured(target)

    except Exception as e:
        return MitmResult(target=target, error=f"Capture failed: {e}")


def get_captured(target: str) -> MitmResult:
    """Read saved flows file and return parsed request/response pairs."""
    flows_file = _flows_path(target)

    if not flows_file.exists():
        return MitmResult(
            target=target,
            error=f"No flows file at {flows_file} — run capture_traffic first",
        )

    try:
        from mitmproxy import io as mitmio
        from mitmproxy.http import HTTPFlow

        captured = []
        with open(flows_file, "rb") as f:
            reader = mitmio.FlowReader(f)
            for flow in reader.stream():
                if not isinstance(flow, HTTPFlow):
                    continue
                req  = flow.request
                resp = flow.response
                captured.append(CapturedRequest(
                    method=req.method,
                    url=req.pretty_url,
                    status_code=resp.status_code if resp else None,
                    request_headers=dict(req.headers),
                    response_headers=dict(resp.headers) if resp else {},
                    content_type=resp.headers.get("content-type", "") if resp else "",
                ))

        return MitmResult(target=target, requests=captured, flows_file=str(flows_file))

    except ImportError:
        return MitmResult(
            target=target,
            error="mitmproxy Python package not installed — run: pip install mitmproxy>=10.0.0",
        )
    except Exception as e:
        return MitmResult(target=target, error=f"Failed to read flows: {e}")


_INTERESTING_HEADERS = (
    "authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-csrf-token",
)


def format_for_agent(result: MitmResult) -> str:
    if result.error:
        return f"MITMPROXY ERROR: {result.error}"

    if not result.requests:
        return f"mitmproxy capture complete for {result.target}. No HTTP requests captured."

    lines = [
        f"mitmproxy capture complete for {result.target}.",
        f"Captured {len(result.requests)} request(s):\n",
    ]

    for i, r in enumerate(result.requests, 1):
        status = str(r.status_code) if r.status_code is not None else "no response"
        lines.append(f"  [{i}] {r.method} {r.url}  →  {status}")
        if r.content_type:
            lines.append(f"      Content-Type: {r.content_type}")
        for h in _INTERESTING_HEADERS:
            val = r.request_headers.get(h) or r.response_headers.get(h)
            if val:
                lines.append(f"      {h}: {val[:120]}")

    return "\n".join(lines)
