import re
from pathlib import Path
from datetime import datetime
from docx import Document
from docx.shared import Pt, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import parse_xml

def _get_project_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "config.yaml").exists():
            return parent
    fallback = Path.home() / "clawstrike"
    if fallback.exists():
        return fallback
    return Path.cwd()


_PROJECT_ROOT = _get_project_root()
ENGAGEMENTS_DIR = _PROJECT_ROOT / "engagements"
REPORTS_DIR     = _PROJECT_ROOT / "reports"
ENGAGEMENTS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# CVSS baseline estimates by service name
CVSS_MAP = {
    "ssh":     ("Medium",   "5.3", "Exposed SSH service — check for weak creds / outdated version"),
    "http":    ("High",     "7.5", "Unencrypted HTTP — data interception risk, directory exposure"),
    "https":   ("Medium",   "5.0", "HTTPS service — check TLS version and certificate validity"),
    "ftp":     ("High",     "7.5", "FTP — often allows anonymous login or transmits creds in cleartext"),
    "mysql":   ("Critical", "9.1", "Database port exposed — check for unauthenticated access"),
    "ms-sql":  ("Critical", "9.1", "MSSQL exposed — check for default credentials"),
    "rdp":     ("High",     "8.1", "RDP exposed — BlueKeep / brute-force risk"),
    "smb":     ("Critical", "9.8", "SMB exposed — EternalBlue / relay attack surface"),
    "smtp":    ("Medium",   "5.3", "SMTP open — check for open relay and user enumeration"),
    "dns":     ("Medium",   "5.3", "DNS exposed — check for zone transfer (AXFR)"),
    "redis":   ("Critical", "9.8", "Redis exposed — often unauthenticated, RCE via config write"),
    "mongodb": ("Critical", "9.8", "MongoDB exposed — often unauthenticated"),
}
DEFAULT_CVSS = ("Low", "3.1", "Service exposed — review necessity and access controls")

# severity → (bg hex, text RGBColor, use white text?)
SEVERITY_STYLE = {
    "Critical": ("C00000", RGBColor(0xC0, 0x00, 0x00), True),
    "High":     ("FF4000", RGBColor(0xFF, 0x40, 0x00), True),
    "Medium":   ("FFA500", RGBColor(0xFF, 0xA5, 0x00), False),
    "Low":      ("007040", RGBColor(0x00, 0x70, 0x40), True),
}


# ── helpers ───────────────────────────────────────────────────────────────────

def _cvss_for_service(service: str) -> tuple:
    s = service.lower()
    for key, val in CVSS_MAP.items():
        if key in s:
            return val
    return DEFAULT_CVSS


def _set_cell_bg(cell, hex_color: str):
    """Fill a table cell with a solid background colour."""
    shading = parse_xml(
        f'<w:shd xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        f'w:val="clear" w:color="auto" w:fill="{hex_color}"/>'
    )
    cell._tc.get_or_add_tcPr().append(shading)


def _style_severity_cell(cell, severity: str):
    """Apply background + text colour to a severity or CVSS cell."""
    if severity not in SEVERITY_STYLE:
        return
    bg_hex, text_rgb, white_text = SEVERITY_STYLE[severity]
    _set_cell_bg(cell, bg_hex)
    for para in cell.paragraphs:
        for run in para.runs:
            run.bold = True
            run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF) if white_text else RGBColor(0x00, 0x00, 0x00)


def _add_poc_step(doc, number: int, label: str, command: str):
    """Add a numbered PoC step with a monospace command block."""
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Inches(0.2)
    run = p.add_run(f"{number}. {label}")
    run.bold = True

    cmd_para = doc.add_paragraph()
    cmd_para.paragraph_format.left_indent = Inches(0.4)
    # light grey shading on the command paragraph
    pPr = cmd_para._p.get_or_add_pPr()
    shd = parse_xml(
        '<w:shd xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'w:val="clear" w:color="auto" w:fill="F2F2F2"/>'
    )
    pPr.append(shd)
    cmd_run = cmd_para.add_run(command)
    cmd_run.font.name = "Courier New"
    cmd_run.font.size = Pt(9)


def _is_md_separator(line: str) -> bool:
    """True for lines like |---|---| or --- or ===."""
    stripped = line.strip()
    if re.match(r"^\|[-| :]+\|$", stripped):
        return True
    if re.match(r"^[-=]{3,}$", stripped):
        return True
    return False


def _render_analysis(doc, text: str):
    """
    Convert agent analysis markdown into proper docx elements.
    Handles: tables, headings, bullets, numbered lists, plain paragraphs.
    Skips raw markdown separators and pipe-only lines.
    """
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]

        # skip separator lines (--- / |---|)
        if _is_md_separator(line):
            i += 1
            continue

        # markdown table block — collect all consecutive | lines
        if line.strip().startswith("|"):
            table_lines = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                if not _is_md_separator(lines[i]):
                    table_lines.append(lines[i])
                i += 1

            if not table_lines:
                continue

            # parse rows
            rows = []
            for tl in table_lines:
                cells = [c.strip() for c in tl.strip().strip("|").split("|")]
                rows.append(cells)

            if not rows:
                continue

            cols = max(len(r) for r in rows)
            tbl = doc.add_table(rows=len(rows), cols=cols)
            tbl.style = "Table Grid"
            for r_idx, row in enumerate(rows):
                for c_idx in range(cols):
                    val = row[c_idx] if c_idx < len(row) else ""
                    cell = tbl.cell(r_idx, c_idx)
                    cell.text = _strip_inline_md(val)
                    if r_idx == 0:
                        cell.paragraphs[0].runs[0].bold = True if cell.paragraphs[0].runs else None
            doc.add_paragraph()
            continue

        # heading ## / ###
        m = re.match(r"^(#{1,3})\s+(.*)", line)
        if m:
            level_str, heading_text = m.group(1), m.group(2)
            p = doc.add_paragraph()
            run = p.add_run(_strip_inline_md(heading_text))
            run.bold = True
            run.font.size = Pt(12 if len(level_str) == 1 else 11)
            i += 1
            continue

        # bullet list  - item / * item
        m = re.match(r"^[\-\*]\s+(.*)", line)
        if m:
            doc.add_paragraph(_strip_inline_md(m.group(1)), style="List Bullet")
            i += 1
            continue

        # numbered list  1. item
        m = re.match(r"^\d+\.\s+(.*)", line)
        if m:
            doc.add_paragraph(_strip_inline_md(m.group(1)), style="List Number")
            i += 1
            continue

        # blank line → skip
        if not line.strip():
            i += 1
            continue

        # plain paragraph — collect consecutive non-special lines
        para_lines = []
        while i < len(lines):
            l = lines[i]
            if (not l.strip()
                    or l.strip().startswith("|")
                    or re.match(r"^(#{1,3}|\s*[\-\*]\s|\d+\.)\s", l)
                    or _is_md_separator(l)):
                break
            para_lines.append(_strip_inline_md(l))
            i += 1
        if para_lines:
            doc.add_paragraph(" ".join(para_lines))

    return


def _strip_inline_md(text: str) -> str:
    """Remove inline markdown: bold, italic, code, but preserve content."""
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"\*(.+?)\*",     r"\1", text)
    text = re.sub(r"__(.+?)__",     r"\1", text)
    text = re.sub(r"_(.+?)_",       r"\1", text)
    text = re.sub(r"`(.+?)`",       r"\1", text)
    return text.strip()


# ── engagement parser ─────────────────────────────────────────────────────────

def _parse_engagement(md_path: Path) -> dict:
    text = md_path.read_text(encoding="utf-8")
    data = {"target": "", "timestamp": "", "ports": [], "analysis": ""}

    m = re.search(r"\*\*Target:\*\*\s*`([^`]+)`", text)
    if m:
        data["target"] = m.group(1)

    m = re.search(r"\*\*Timestamp:\*\*\s*(.+?)  ", text)
    if m:
        data["timestamp"] = m.group(1).strip()

    for row in re.finditer(r"\|\s*(\d+)\s*\|\s*(\w+)\s*\|\s*(\w*)\s*\|\s*([^|]*)\s*\|", text):
        port, proto, service, version = row.groups()
        data["ports"].append({
            "port":     port,
            "protocol": proto,
            "service":  service,
            "version":  version.strip().strip("—").strip(),
        })

    m = re.search(r"## Agent Analysis\s*\n([\s\S]+)", text)
    if m:
        data["analysis"] = m.group(1).strip()

    return data


# ── main generator ────────────────────────────────────────────────────────────

def generate_report(target: str, output_dir: Path = None) -> str:
    if output_dir is None:
        output_dir = REPORTS_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    pattern = f"{target.replace('/', '_').replace(':', '_')}_*.md"
    files   = sorted(ENGAGEMENTS_DIR.glob(pattern))

    if not files:
        return f"ERROR: no engagement files found for target '{target}' in {ENGAGEMENTS_DIR}"

    all_ports        = []
    latest_analysis  = ""
    latest_timestamp = ""
    for f in files:
        eng = _parse_engagement(f)
        all_ports.extend(eng["ports"])
        latest_analysis  = eng["analysis"]  or latest_analysis
        latest_timestamp = eng["timestamp"] or latest_timestamp

    seen, unique_ports = set(), []
    for p in all_ports:
        key = (p["port"], p["protocol"])
        if key not in seen:
            seen.add(key)
            unique_ports.append(p)

    doc = Document()

    for section in doc.sections:
        section.top_margin    = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin   = Inches(1.2)
        section.right_margin  = Inches(1.2)

    # ── cover page ────────────────────────────────────────────────────────────
    for _ in range(4):
        doc.add_paragraph()

    title_p = doc.add_paragraph()
    title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    t = title_p.add_run("VULNERABILITY ASSESSMENT REPORT")
    t.bold = True
    t.font.size = Pt(24)
    t.font.color.rgb = RGBColor(0xC0, 0x00, 0x00)

    doc.add_paragraph()

    subtitle_p = doc.add_paragraph()
    subtitle_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    s = subtitle_p.add_run("Penetration Test Report — CONFIDENTIAL")
    s.font.size = Pt(13)
    s.font.color.rgb = RGBColor(0x40, 0x40, 0x40)

    for _ in range(3):
        doc.add_paragraph()

    # cover info table (no border, just layout)
    cover_tbl = doc.add_table(rows=4, cols=2)
    cover_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cover_data = [
        ("Target",          target),
        ("Date",            datetime.utcnow().strftime("%B %d, %Y")),
        ("Classification",  "CONFIDENTIAL"),
        ("Prepared by",     "ClawStrike OS"),
    ]
    for i, (label, value) in enumerate(cover_data):
        lbl_cell = cover_tbl.cell(i, 0)
        val_cell = cover_tbl.cell(i, 1)
        lbl_run = lbl_cell.paragraphs[0].add_run(label)
        lbl_run.bold = True
        lbl_run.font.size = Pt(11)
        val_run = val_cell.paragraphs[0].add_run(value)
        val_run.font.size = Pt(11)

    doc.add_page_break()

    # ── 1. executive summary ──────────────────────────────────────────────────
    doc.add_heading("1. Executive Summary", level=1)
    severities = [_cvss_for_service(p["service"])[0] for p in unique_ports]
    crit = severities.count("Critical")
    high = severities.count("High")
    med  = severities.count("Medium")
    low  = severities.count("Low")

    doc.add_paragraph(
        f"A vulnerability assessment was conducted against the target host {target}. "
        f"The scan identified {len(unique_ports)} open service(s). "
        f"Of these, {crit} were rated Critical, {high} High, {med} Medium, and {low} Low severity "
        f"based on CVSS v3.1 baseline estimates. "
        f"Immediate remediation is recommended for all Critical and High findings."
    )

    # ── 2. scope ──────────────────────────────────────────────────────────────
    doc.add_heading("2. Scope", level=1)
    scope_tbl = doc.add_table(rows=2, cols=2)
    scope_tbl.style = "Table Grid"
    scope_tbl.cell(0, 0).text = "Target"
    scope_tbl.cell(0, 1).text = target
    scope_tbl.cell(1, 0).text = "Scan Date"
    scope_tbl.cell(1, 1).text = latest_timestamp or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    doc.add_paragraph()

    # ── 3. findings table ─────────────────────────────────────────────────────
    doc.add_heading("3. Findings", level=1)

    headers = ["Port", "Protocol", "Service", "Version", "Severity", "CVSS", "Description"]
    tbl = doc.add_table(rows=1, cols=len(headers))
    tbl.style = "Table Grid"
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER

    # header row — dark background
    hdr_row = tbl.rows[0]
    for i, h in enumerate(headers):
        cell = hdr_row.cells[i]
        _set_cell_bg(cell, "222222")
        p = cell.paragraphs[0]
        run = p.add_run(h)
        run.bold = True
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)

    for p in unique_ports:
        severity, cvss, desc = _cvss_for_service(p["service"])
        row = tbl.add_row()
        values = [p["port"], p["protocol"], p["service"], p["version"] or "—", severity, cvss, desc]
        for i, val in enumerate(values):
            cell = row.cells[i]
            cell.text = val
            if i == 4:  # Severity
                _style_severity_cell(cell, severity)
            elif i == 5:  # CVSS score
                _style_severity_cell(cell, severity)
                # also make text larger
                cell.paragraphs[0].runs[0].font.size = Pt(11)

    doc.add_paragraph()

    # ── 4. proof of concept steps ─────────────────────────────────────────────
    doc.add_heading("4. Proof of Concept Steps", level=1)

    for p in unique_ports:
        severity, cvss, desc = _cvss_for_service(p["service"])
        doc.add_heading(f"Port {p['port']}/{p['protocol']} — {p['service'].upper()}", level=2)

        # severity badge row
        badge_tbl = doc.add_table(rows=1, cols=2)
        sev_cell  = badge_tbl.cell(0, 0)
        cvss_cell = badge_tbl.cell(0, 1)
        sev_cell.text  = f"Severity: {severity}"
        cvss_cell.text = f"CVSS v3.1: {cvss}"
        _style_severity_cell(sev_cell,  severity)
        _style_severity_cell(cvss_cell, severity)
        doc.add_paragraph()

        doc.add_paragraph(desc)

        svc = p["service"].lower()
        if "ssh" in svc:
            _add_poc_step(doc, 1, "Confirm SSH version",
                          f"nmap -sV -p 22 {target}")
            _add_poc_step(doc, 2, "Audit ciphers and algorithms",
                          f"ssh-audit {target}")
            _add_poc_step(doc, 3, "Test for weak credentials (authorized engagement only)",
                          f"hydra -l root -P wordlist.txt ssh://{target}")
        elif "http" in svc and "https" not in svc:
            _add_poc_step(doc, 1, "Directory brute-force",
                          f"gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt")
            _add_poc_step(doc, 2, "Banner grab",
                          f"curl -I http://{target}")
            _add_poc_step(doc, 3, "Web vulnerability scan",
                          f"nikto -h http://{target}")
        elif "https" in svc or "ssl" in svc:
            _add_poc_step(doc, 1, "Check TLS configuration",
                          f"sslscan {target}")
            _add_poc_step(doc, 2, "Directory brute-force",
                          f"gobuster dir -u https://{target} -w /usr/share/wordlists/dirb/common.txt")
        elif "mysql" in svc or "ms-sql" in svc:
            _add_poc_step(doc, 1, "Enumerate service",
                          f"nmap -sV --script=mysql-info,mysql-enum -p {p['port']} {target}")
            _add_poc_step(doc, 2, "Test default credentials (authorized engagement only)",
                          f"mysql -h {target} -u root -p")
        elif "ftp" in svc:
            _add_poc_step(doc, 1, "Check anonymous login",
                          f"nmap --script=ftp-anon -p 21 {target}")
            _add_poc_step(doc, 2, "Connect and list files",
                          f"ftp {target}")
        elif "smb" in svc:
            _add_poc_step(doc, 1, "Enumerate shares",
                          f"smbclient -L //{target} -N")
            _add_poc_step(doc, 2, "Check for EternalBlue",
                          f"nmap --script=smb-vuln-ms17-010 -p 445 {target}")
        elif "rdp" in svc:
            _add_poc_step(doc, 1, "Check for BlueKeep",
                          f"nmap --script=rdp-vuln-ms12-020 -p 3389 {target}")
        elif "redis" in svc:
            _add_poc_step(doc, 1, "Test unauthenticated access",
                          f"redis-cli -h {target} ping")
            _add_poc_step(doc, 2, "Enumerate keys",
                          f"redis-cli -h {target} keys '*'")
        else:
            _add_poc_step(doc, 1, "Version detection",
                          f"nmap -sV -p {p['port']} {target}")
            _add_poc_step(doc, 2, "Search for known CVEs",
                          f"searchsploit {p['service']}")

        doc.add_paragraph()

    # ── 5. recommendations ────────────────────────────────────────────────────
    doc.add_heading("5. Recommendations", level=1)
    for rec in [
        "Disable or restrict access to all non-essential services using firewall rules.",
        "Enforce key-based authentication on SSH and disable password login.",
        "Ensure all services are running the latest patched versions.",
        "Implement network segmentation to limit lateral movement.",
        "Deploy an IDS/IPS solution to monitor for exploitation attempts.",
        "Conduct regular vulnerability assessments and penetration tests.",
        "Apply the principle of least privilege to all exposed services.",
    ]:
        doc.add_paragraph(rec, style="List Bullet")

    # ── 6. agent analysis ─────────────────────────────────────────────────────
    if latest_analysis:
        doc.add_heading("6. Agent Analysis", level=1)
        _render_analysis(doc, latest_analysis)

    # ── 7. evidence ───────────────────────────────────────────────────────────
    safe_target  = target.replace("/", "_").replace(":", "_")
    evidence_dir = ENGAGEMENTS_DIR / safe_target / "evidence"
    ev_files     = sorted(evidence_dir.glob("*.txt")) if evidence_dir.exists() else []

    if ev_files:
        doc.add_heading("7. Evidence", level=1)
        doc.add_paragraph(
            f"The following {len(ev_files)} evidence file(s) were captured automatically "
            "during the engagement."
        )

        for ev_file in ev_files:
            doc.add_heading(ev_file.name, level=2)
            content = ev_file.read_text(encoding="utf-8", errors="replace")
            # trim very large files so the docx stays manageable
            if len(content) > 4000:
                content = content[:4000] + f"\n\n[... {len(content) - 4000} bytes truncated ...]"
            para = doc.add_paragraph()
            run  = para.add_run(content)
            run.font.name = "Courier New"
            run.font.size = Pt(8)
            doc.add_paragraph()

    # ── save ──────────────────────────────────────────────────────────────────
    timestamp   = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_path    = output_dir / f"{safe_target}_{timestamp}.docx"
    doc.save(str(out_path))
    return str(out_path)
