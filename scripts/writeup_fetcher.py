"""
ClawStrike — Writeup Fetcher (v3)
==================================
Fetches pentesting writeups from any URL, extracts relevant content,
and formats it into raw data files organized by training layer.

Fixes from v2:
- Output directory based on detected platform (htb/vulnhub/thm), not layer
- AI extraction pulls only layer-relevant content
- Proper markdown handling for GitHub raw URLs

Usage:
  python scripts/writeup_fetcher.py <links_file> [--layer N]

Examples:
  python scripts/writeup_fetcher.py links/htb_easy.txt --layer 1
  python scripts/writeup_fetcher.py links/vulnhub.txt --layer 1
  python scripts/writeup_fetcher.py links/vulnhub.txt --layer 3
"""

import argparse
import os
import re
import sys
import json
import time
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("ERROR: Missing dependencies. Run:")
    print("  pip install requests beautifulsoup4")
    sys.exit(1)

try:
    from anthropic import Anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

RAW_DIR = Path.home() / "clawstrike-data" / "raw"
LINKS_DIR = Path.home() / "clawstrike-data" / "links"
META_DIR = Path.home() / "clawstrike-data" / "metadata"

for d in [RAW_DIR, LINKS_DIR, META_DIR]:
    d.mkdir(parents=True, exist_ok=True)

LAYER_CONFIG = {
    1: {
        "name": "Recon Decision Trees",
        "focus": "reconnaissance and enumeration",
        "extract_prompt": """Extract ONLY the reconnaissance and enumeration phase from this writeup.

Include:
1. The exact nmap/scan output (raw, not summarized)
2. What the author tried first after seeing the scan and WHY
3. Every enumeration command they ran with actual output
4. Any failed attempts during recon — what didn't work and why
5. How they pivoted when something failed
6. Their reasoning for choosing the next step at each decision point
7. What they decided NOT to try and why

DO NOT include:
- Exploitation steps (getting the shell)
- Privilege escalation
- Flag captures
- Summary sections or bullet-point conclusions

Write it as a raw narrative walkthrough showing actual decision-making with real command outputs.""",
    },
    2: {
        "name": "Tool Output Parsing",
        "focus": "tool outputs and their interpretation",
        "extract_prompt": """Extract ALL raw tool outputs from this writeup and how the author interpreted them.

Include:
1. Every raw tool output shown (nmap, gobuster, nikto, sqlmap, enum4linux, smbclient, etc.)
2. What the author noticed in each output — what was important vs noise
3. How they filtered findings by severity
4. What they concluded from each tool's output
5. What they decided to do based on each output

Format each tool output block as:
TOOL: [tool name]
COMMAND: [exact command run]
RAW OUTPUT:
[paste the output]
AUTHOR ANALYSIS:
[what they said about the output]

DO NOT include exploitation or privilege escalation steps.""",
    },
    3: {
        "name": "Failed Paths + Pivots",
        "focus": "failed attempts and how the author recovered",
        "extract_prompt": """Extract ONLY the failed attempts, dead ends, and pivot decisions from this writeup.

Include:
1. Every action that did NOT work
2. The exact error or unexpected result
3. The author's reasoning about WHY it failed
4. What they tried next and why they chose that path
5. Any rabbit holes they went down before finding the right path
6. Times they had to change strategy entirely

Focus on the FAILURES and PIVOTS, not the successful path.
Include the actual commands and error outputs when available.
DO NOT include steps that worked on the first try unless they came after a failure.""",
    },
    4: {
        "name": "Exploit Ranking",
        "focus": "vulnerability assessment and exploit selection",
        "extract_prompt": """Extract the vulnerability assessment and exploit selection reasoning from this writeup.

Include:
1. All vulnerabilities discovered during enumeration
2. How the author prioritized which to exploit first
3. Their reasoning about exploit probability and impact
4. Which exploits they considered and why they chose the one they did
5. Any discussion of exploit reliability or risk
6. Services/versions found and their known vulnerability status

I need to understand the RANKING LOGIC — why they chose path A over path B.
Include version numbers, CVE references, and the author's risk assessment.

DO NOT include the actual exploitation steps or post-exploitation.
Focus on the DECISION of what to exploit and WHY.""",
    },
    5: {
        "name": "Post-Exploitation Reasoning",
        "focus": "post-exploitation and privilege escalation",
        "extract_prompt": """Extract ONLY the post-exploitation and privilege escalation phase from this writeup.

Include:
1. What access level they had after initial exploitation
2. First commands run after getting a shell
3. System enumeration steps (LinPEAS, WinPEAS, manual checks)
4. How they identified the privilege escalation vector
5. What they checked and in what order
6. Failed privesc attempts before the successful one
7. Credential harvesting
8. Any lateral movement or network reconnaissance

Focus on the REASONING — why they checked certain things first,
how they prioritized privesc vectors, what they ignored and why.

DO NOT include the initial exploitation (getting the first shell).
Start from the point where they have a shell and are escalating.""",
    },
    6: {
        "name": "Reporting Intelligence",
        "focus": "vulnerability findings and report writing",
        "extract_prompt": """Extract all vulnerability findings from this writeup in a format suitable for professional reporting.

For each vulnerability found, extract:
1. What was vulnerable (service, version, configuration)
2. How it was discovered
3. What the impact was (what access it gave)
4. The evidence chain (commands + outputs proving the vulnerability)
5. Any CVE or advisory references

Format each finding separately with clear evidence.
DO NOT editorialize — just extract the raw findings with evidence.""",
    },
    7: {
        "name": "Ethics + Scope Enforcement",
        "focus": "scope boundaries and ethical decisions",
        "extract_prompt": """Extract any mentions of scope, authorization, or ethical boundaries from this writeup.

Include:
1. Any time the author mentioned staying within scope
2. Systems discovered that were NOT targeted and why
3. Decisions to NOT exploit something (and reasoning)
4. Any discussion of responsible disclosure
5. References to rules of engagement

If the writeup doesn't explicitly discuss ethics/scope, note that.""",
    },
}


# ── Platform Detection ──────────────────────────────────────────────────────

def detect_platform(url: str, page_text: str = "") -> str:
    """Detect platform from URL and content. Returns folder name."""
    url_lower = url.lower()
    text_lower = page_text[:2000].lower() if page_text else ""

    if "htb" in url_lower or "hackthebox" in url_lower:
        return "htb"
    if "tryhackme" in url_lower or "thm" in url_lower:
        return "thm"
    if "vulnhub" in url_lower:
        return "vulnhub"

    # Check content for platform mentions
    if "hack the box" in text_lower or "hackthebox" in text_lower or "htb" in text_lower:
        return "htb"
    if "tryhackme" in text_lower:
        return "thm"
    if "vulnhub" in text_lower:
        return "vulnhub"

    return "other"


def detect_source(url: str) -> str:
    domain = urlparse(url).netloc.lower()
    source_map = {
        "0xdf.gitlab.io": "0xdf",
        "rana-khalil.gitbook.io": "rana-khalil",
        "blog.razrsec.uk": "razrsec",
        "medium.com": "medium",
        "infosecwriteups.com": "infosecwriteups",
        "hacktricks.xyz": "hacktricks",
        "book.hacktricks.xyz": "hacktricks",
        "raw.githubusercontent.com": "github",
        "github.com": "github",
    }
    for key, source in source_map.items():
        if key in domain:
            return source
    return domain.replace(".", "_")


def extract_box_name(url: str, page_text: str, page_title: str) -> str:
    path = urlparse(url).path

    # 0xdf pattern: htb-lame.html
    htb_match = re.search(r"htb-(\w+)", path, re.IGNORECASE)
    if htb_match:
        return htb_match.group(1).capitalize()

    # VulnHub pattern: Vulnhub-Jigsaw.md
    vulnhub_match = re.search(r"[Vv]ulnhub[_-](\w+)\.md", path)
    if vulnhub_match:
        return vulnhub_match.group(1).capitalize()

    # Date-prefixed GitHub files: 2019-07-02-Something-Name.md
    date_match = re.search(r"\d{4}-\d{2}-\d{2}-(.+?)\.md", path)
    if date_match:
        raw_name = date_match.group(1)
        cleaned = re.sub(r"^(vulnhub|htb|hackthebox|tryhackme)[_-]", "", raw_name, flags=re.IGNORECASE)
        parts = cleaned.split("-")
        name = parts[-1] if len(parts) > 1 else parts[0]
        return name.replace("_", " ").strip().capitalize()

    # Title patterns
    if page_title:
        title_patterns = [
            r"HTB:\s*(\w+)", r"HackTheBox\s*[-–]\s*(\w+)",
            r"(\w+)\s*[-–]\s*HTB", r"VulnHub\s*[-–]\s*(\w+)",
            r"Vulnhub\s*[-–]\s*(\w+)", r"(\w+)\s+writeup",
            r"(\w+)\s*[-–]\s*writeup",
        ]
        for pattern in title_patterns:
            match = re.search(pattern, page_title, re.IGNORECASE)
            if match:
                return match.group(1).strip().capitalize()

    # Content-based
    if page_text:
        for pattern in [r"[Mm]achine[:\s]+(\w+)", r"[Bb]ox[:\s]+(\w+)"]:
            match = re.search(pattern, page_text[:1000])
            if match:
                name = match.group(1)
                if name.lower() not in ("the", "this", "a", "an", "is", "setup", "name"):
                    return name.capitalize()

    # Final fallback
    segments = [s for s in path.strip("/").split("/") if s]
    if segments:
        name = segments[-1]
        name = re.sub(r"\.(html?|md|txt)$", "", name)
        name = re.sub(r"^\d{4}-\d{2}-\d{2}-?", "", name)
        name = name.replace("-", "_").strip("_")
        if name:
            return name.capitalize()

    return "unknown"


def is_raw_text_url(url: str) -> bool:
    parsed = urlparse(url)
    if "raw.githubusercontent.com" in parsed.netloc:
        return True
    if parsed.path.lower().endswith((".md", ".txt", ".rst")):
        return True
    return False


def fetch_page(url: str) -> tuple[str, str, str]:
    headers = {"User-Agent": "Mozilla/5.0 (compatible; ClawStrike-DataPipeline/1.0)"}

    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        return "", "", f"Failed to fetch {url}: {e}"

    # Raw text/markdown — return as-is
    if is_raw_text_url(url):
        raw_text = resp.text
        title = ""
        title_match = re.search(r"^#\s+(.+)$", raw_text, re.MULTILINE)
        if title_match:
            title = title_match.group(1).strip()
        else:
            fm_match = re.search(r"title:\s*(.+)", raw_text)
            if fm_match:
                title = fm_match.group(1).strip()
        raw_text = re.sub(r"^---\s*\n.*?\n---\s*\n", "", raw_text, flags=re.DOTALL)
        return raw_text, title, ""

    # HTML page
    soup = BeautifulSoup(resp.text, "html.parser")
    title = soup.title.string.strip() if soup.title and soup.title.string else ""

    for tag in soup.find_all(["script", "style", "nav", "footer", "header",
                               "aside", "iframe", "noscript"]):
        tag.decompose()

    content = None
    for selector in ["article", ".post-content", ".entry-content",
                     ".article-content", ".content", ".markdown-body",
                     "main", "#content", ".post"]:
        found = soup.select_one(selector)
        if found:
            content = found
            break

    if not content:
        content = soup.body if soup.body else soup

    text_parts = []
    for element in content.descendants:
        if element.name in ("pre", "code"):
            text_parts.append(f"\n```\n{element.get_text()}\n```\n")
        elif element.name in ("h1", "h2", "h3", "h4"):
            text_parts.append(f"\n{'#' * int(element.name[1])} {element.get_text().strip()}\n")
        elif element.name == "p":
            text_parts.append(element.get_text().strip() + "\n")
        elif element.name == "li":
            text_parts.append(f"- {element.get_text().strip()}\n")

    raw_text = "".join(text_parts)
    if len(raw_text.strip()) < 200:
        raw_text = content.get_text(separator="\n", strip=True)

    raw_text = re.sub(r"\n{4,}", "\n\n\n", raw_text)
    return raw_text, title, ""


def ai_extract(raw_text: str, layer: int, box_name: str, source: str) -> str:
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not HAS_ANTHROPIC or not api_key:
        print("  [!] No Anthropic API key — saving raw text")
        return raw_text

    layer_cfg = LAYER_CONFIG[layer]
    client = Anthropic(api_key=api_key)

    prompt = f"""You are extracting training data from a penetration testing writeup.

Box: {box_name}
Source: {source}
Layer: {layer} — {layer_cfg['name']}

{layer_cfg['extract_prompt']}

--- WRITEUP CONTENT ---

{raw_text[:15000]}"""

    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text
    except Exception as e:
        print(f"  [!] API error: {e} — saving raw text instead")
        return raw_text


def save_raw_file(content: str, box_name: str, source: str,
                  platform: str, layer: int, url: str) -> Path:
    """Save to platform-specific directory. Never overwrites."""

    layer_cfg = LAYER_CONFIG[layer]

    # Save to platform directory (htb/, vulnhub/, thm/, other/)
    subdir = RAW_DIR / platform
    subdir.mkdir(parents=True, exist_ok=True)

    # Unique filename: source_boxname.txt
    safe_source = re.sub(r"[^a-z0-9]", "_", source.lower())
    safe_name = re.sub(r"[^a-z0-9]", "_", box_name.lower())
    base_filename = f"{safe_source}_{safe_name}"

    filename = f"{base_filename}.txt"
    filepath = subdir / filename
    counter = 2
    while filepath.exists():
        filename = f"{base_filename}_{counter}.txt"
        filepath = subdir / filename
        counter += 1

    platform_display = {
        "htb": "HTB", "vulnhub": "VulnHub",
        "thm": "TryHackMe", "other": "Other"
    }.get(platform, platform.upper())

    header = f"""{'=' * 75}
{platform_display}: {box_name.upper()} — {layer_cfg['name'].upper()} (Layer {layer})
{'=' * 75}

Box: {box_name}
Platform: {platform_display}
Source: {source}
URL: {url}
Layer: {layer} — {layer_cfg['name']}
Extracted: {datetime.now().strftime('%Y-%m-%d %H:%M')}

{'=' * 75}

"""

    with open(filepath, "w") as f:
        f.write(header + content)
    return filepath


def log_metadata(box_name: str, source: str, url: str,
                 platform: str, layer: int, filepath: Path, status: str):
    tracker = META_DIR / "fetch_tracker.jsonl"
    entry = {
        "box_name": box_name,
        "source": source,
        "url": url,
        "platform": platform,
        "layer": layer,
        "output_file": str(filepath),
        "status": status,
        "timestamp": datetime.now().isoformat(),
    }
    with open(tracker, "a") as f:
        f.write(json.dumps(entry) + "\n")


def process_url(url: str, layer: int, use_ai: bool = True) -> bool:
    url = url.strip()
    if not url or url.startswith("#"):
        return False

    print(f"\n{'─' * 60}")
    print(f"  URL: {url}")

    raw_text, title, error = fetch_page(url)
    if error:
        print(f"  ERROR: {error}")
        log_metadata("unknown", "unknown", url, "unknown", layer, Path(""), f"FETCH_ERROR: {error}")
        return False

    source = detect_source(url)
    box_name = extract_box_name(url, raw_text, title)
    platform = detect_platform(url, raw_text)

    print(f"  Box: {box_name}")
    print(f"  Platform: {platform}")
    print(f"  Source: {source}")
    print(f"  Layer: {layer} — {LAYER_CONFIG[layer]['name']}")
    print(f"  Content: {len(raw_text.split())} words")
    print(f"  Type: {'Raw markdown' if is_raw_text_url(url) else 'HTML page'}")
    print(f"  Saving to: raw/{platform}/")

    if len(raw_text.split()) < 100:
        print(f"  WARNING: Very short content — may not extract well")

    if use_ai:
        print(f"  Extracting {LAYER_CONFIG[layer]['focus']}...")
        content = ai_extract(raw_text, layer, box_name, source)
    else:
        content = raw_text

    filepath = save_raw_file(content, box_name, source, platform, layer, url)
    log_metadata(box_name, source, url, platform, layer, filepath, "OK")

    print(f"  ✓ Saved → {filepath}")
    return True


def process_links_file(links_file: str, layer: int, use_ai: bool = True):
    path = Path(links_file)
    if not path.exists():
        print(f"ERROR: Links file not found: {links_file}")
        sys.exit(1)

    urls = [line.strip() for line in path.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")]

    if not urls:
        print(f"ERROR: No URLs found in {links_file}")
        sys.exit(1)

    layer_cfg = LAYER_CONFIG[layer]
    print(f"\n{'═' * 60}")
    print(f"  ClawStrike Writeup Fetcher v3")
    print(f"  Layer {layer}: {layer_cfg['name']}")
    print(f"  URLs to process: {len(urls)}")
    print(f"  AI extraction: {'enabled' if use_ai else 'disabled'}")
    print(f"  Output: auto-sorted by platform (htb/vulnhub/thm/other)")
    print(f"{'═' * 60}")

    success = 0
    failed = 0

    for i, url in enumerate(urls, 1):
        print(f"\n  [{i}/{len(urls)}]", end="")
        try:
            if process_url(url, layer, use_ai):
                success += 1
            else:
                failed += 1
        except Exception as e:
            print(f"  UNEXPECTED ERROR: {e}")
            failed += 1

        if i < len(urls):
            time.sleep(2)

    print(f"\n{'═' * 60}")
    print(f"  Done! {success} succeeded, {failed} failed")
    print(f"  Files auto-sorted into: raw/htb/, raw/vulnhub/, raw/thm/, raw/other/")
    print(f"")
    print(f"  Next steps:")
    print(f"  1. Quality check:  python scripts/quality_check.py raw/vulnhub/ --layer {layer}")
    print(f"  2. Extract:        python scripts/writeup_extractor.py raw/vulnhub/")
    print(f"{'═' * 60}")


def main():
    parser = argparse.ArgumentParser(
        description="ClawStrike Writeup Fetcher v3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/writeup_fetcher.py links/htb_boxes.txt --layer 1
  python scripts/writeup_fetcher.py links/vulnhub.txt --layer 1
  python scripts/writeup_fetcher.py links/vulnhub.txt --layer 3
  python scripts/writeup_fetcher.py links/mixed.txt --layer 1  (auto-sorts by platform)
""",
    )

    parser.add_argument("links_file", help="Text file with one URL per line")
    parser.add_argument("--layer", type=int, default=1, choices=range(1, 8),
                        help="Training data layer (1-7, default: 1)")
    parser.add_argument("--no-ai", action="store_true",
                        help="Skip AI extraction — save raw content only")

    args = parser.parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY") and not args.no_ai:
        print("WARNING: ANTHROPIC_API_KEY not set. AI extraction will be skipped.")
        print("Set it with: export ANTHROPIC_API_KEY=your_key_here\n")

    process_links_file(args.links_file, args.layer, use_ai=not args.no_ai)


if __name__ == "__main__":
    main()
