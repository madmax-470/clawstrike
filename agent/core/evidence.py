"""
Evidence capture — automatically saves tool output, HTTP responses,
and raw command results to engagements/<target>/evidence/ after every finding.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_EVIDENCE_ROOT = Path(__file__).resolve().parents[2] / "engagements"


def _evidence_dir(target: str) -> Path:
    safe = target.replace("://", "_").replace("/", "_").replace(":", "_").strip("_")
    path = _EVIDENCE_ROOT / safe / "evidence"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _safe_label(label: str) -> str:
    return label.replace(" ", "_").replace("/", "-").replace(":", "-")[:40]


def save_terminal_output(text: str, label: str, target: str) -> Path:
    """Save raw terminal/tool output as a .txt evidence file."""
    path = _evidence_dir(target) / f"{_timestamp()}_{_safe_label(label)}.txt"
    path.write_text(text, encoding="utf-8")
    return path


def save_http_response(response: dict, label: str, target: str) -> Path:
    """
    Save an HTTP response as an evidence file.
    response dict keys: url, status_code, headers (dict), body (str).
    """
    lines = []
    url         = response.get("url", "")
    status_code = response.get("status_code", "")
    headers     = response.get("headers", {})
    body        = response.get("body", "")

    if url:
        lines.append(f"URL: {url}")
    if status_code:
        lines.append(f"Status: {status_code}")
    if headers:
        lines.append("\n--- Response Headers ---")
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
    if body:
        lines.append("\n--- Response Body ---")
        lines.append(body[:8192])
        if len(body) > 8192:
            lines.append(f"\n[... truncated — {len(body) - 8192} bytes omitted ...]")

    path = _evidence_dir(target) / f"{_timestamp()}_{_safe_label(label)}_http.txt"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def save_command_output(cmd: str, output: str, target: str) -> Path:
    """Save the exact command string and its full output as an evidence file."""
    tool_name = cmd.replace("TOOL_CALL:", "").strip().split()[0] if cmd.strip() else "tool"
    label = _safe_label(tool_name)

    content = f"CMD: {cmd.strip()}\n\n{'─' * 60}\n\n{output}"
    path = _evidence_dir(target) / f"{_timestamp()}_{label}_cmd.txt"
    path.write_text(content, encoding="utf-8")
    return path


def get_evidence(target: str) -> list[Path]:
    """Return all evidence files for a target, sorted oldest-first."""
    evidence_dir = _evidence_dir(target)
    return sorted(evidence_dir.glob("*.txt"))
