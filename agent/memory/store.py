import os
from datetime import datetime
from pathlib import Path

from agent.core.session import ENGAGEMENTS_DIR as _ENG_DIR

ENGAGEMENTS_DIR = Path(_ENG_DIR)


def save_engagement(target: str, scan_result, analysis: str, scope: list = None) -> str:
    """Save a scan result and agent analysis to /engagements/ as markdown."""
    ENGAGEMENTS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_")
    filename = ENGAGEMENTS_DIR / f"{safe_target}_{timestamp}.md"

    scope_line = ", ".join(scope) if scope else "not defined"

    lines = [
        f"# Engagement: {target}",
        f"",
        f"**Target:** `{target}`  ",
        f"**Timestamp:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC  ",
        f"**Scope:** {scope_line}  ",
        f"",
        f"---",
        f"",
        f"## Open Ports",
        f"",
    ]

    if scan_result.error:
        lines.append(f"_Scan error: {scan_result.error}_")
    elif not scan_result.hosts:
        lines.append("_No live hosts found._")
    else:
        for host in scan_result.hosts:
            lines.append(f"### Host: {host.ip} ({host.hostname or 'no hostname'})")
            if host.ports:
                lines.append("")
                lines.append("| Port | Protocol | Service | Version |")
                lines.append("|------|----------|---------|---------|")
                for p in host.ports:
                    lines.append(
                        f"| {p['port']} | {p['protocol']} | {p['service']} | {p['version'] or '—'} |"
                    )
            else:
                lines.append("_No open ports detected._")
            lines.append("")

    lines += [
        f"---",
        f"",
        f"## Agent Analysis",
        f"",
        analysis.strip(),
        f"",
    ]

    filename.write_text("\n".join(lines), encoding="utf-8")
    return str(filename)


def load_engagements(target: str = None) -> list:
    """
    Load engagement markdown files from /engagements/.
    If target is given, only return files whose name starts with that target's safe form.
    Returns a list of dicts: {filename, content}.
    """
    if not ENGAGEMENTS_DIR.exists():
        return []

    files = sorted(ENGAGEMENTS_DIR.glob("*.md"))
    results = []

    for f in files:
        if target:
            safe_target = target.replace("/", "_").replace(":", "_")
            if not f.stem.startswith(safe_target + "_"):
                continue
        results.append({
            "filename": f.name,
            "content": f.read_text(encoding="utf-8"),
        })

    return results
