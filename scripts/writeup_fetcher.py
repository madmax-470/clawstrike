"""
ClawStrike — Writeup Fetcher
=============================
Fetches pentesting writeups from any URL, extracts relevant content,
and formats it into raw data files organized by training layer.

Usage:
  python scripts/writeup_fetcher.py <links_file> [--layer N]

  links_file  = text file with one URL per line
  --layer N   = which layer to format for (1-7, default: 1)

Examples:
  python scripts/writeup_fetcher.py links/htb_easy.txt --layer 1
  python scripts/writeup_fetcher.py links/failures.txt --layer 3
  python scripts/writeup_fetcher.py links/reports.txt --layer 6

Output:
  Raw .txt files saved to ~/clawstrike-data/raw/<source>/<boxname>.txt
  Ready for review, then feeding into writeup_extractor.py

Designed for delegation — give your juniors the links file
and this script. They run it, you review the output.
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

# ── Directories ─────────────────────────────────────────────────────────────

RAW_DIR = Path.home() / "clawstrike-data" / "raw"
LINKS_DIR = Path.home() / "clawstrike-data" / "links"
META_DIR = Path.home() / "clawstrike-data" / "metadata"

for d in [RAW_DIR, LINKS_DIR, META_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ── Layer Definitions ───────────────────────────────────────────────────────

LAYER_CONFIG = {
    1: {
        "name": "Recon Decision Trees",
        "output_subdir": "htb",
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
        "output_subdir": "tool_outputs",
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
        "output_subdir": "failures",
        "focus": "failed attempts and how the author recovered",
        "extract_prompt": """Extract ONLY the failed attempts, dead ends, and pivot decisions from this writeup.

Include:
1. Every action that did NOT work
2. The exact error or unexpected result
3. The author's reasoning about WHY it failed
4. What they tried next and why they chose that path
5. Any rabbit holes they went down before finding the right path
6. Times they had to change strategy entirely

Focus on the FAILURES and PIVOTS, not the successful path. I want to see:
- "I tried X but it didn't work because Y"
- "This looked promising but turned out to be a dead end"
- "The exploit failed so I had to find another way"

Include the actual commands and error outputs when available.
DO NOT include steps that worked on the first try unless they came after a failure.""",
    },
    4: {
        "name": "Exploit Ranking",
        "output_subdir": "exploit_ranking",
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
        "output_subdir": "post_exploit",
        "focus": "post-exploitation and privilege escalation",
        "extract_prompt": """Extract ONLY the post-exploitation and privilege escalation phase from this writeup.

Include:
1. What access level they had after initial exploitation
2. First commands run after getting a shell (whoami, id, uname, etc.)
3. System enumeration steps (LinPEAS, WinPEAS, manual checks)
4. How they identified the privilege escalation vector
5. What they checked and in what order
6. Failed privesc attempts before the successful one
7. Credential harvesting (files found, hashes cracked, keys discovered)
8. Any lateral movement or network reconnaissance from the compromised host

Focus on the REASONING — why they checked certain things first,
how they prioritized privesc vectors, what they ignored and why.

DO NOT include the initial exploitation (getting the first shell).
Start from the point where they have a shell and are escalating.""",
    },
    6: {
        "name": "Reporting Intelligence",
        "output_subdir": "reporting",
        "focus": "vulnerability findings and report writing",
        "extract_prompt": """Extract all vulnerability findings from this writeup in a format suitable for professional reporting.

For each vulnerability found, extract:
1. What was vulnerable (service, version, configuration)
2. How it was discovered
3. What the impact was (what access it gave)
4. The evidence chain (commands + outputs proving the vulnerability)
5. Any CVE or advisory references

Also extract:
- The overall severity of the engagement
- How many steps were needed for full compromise
- Whether credentials were involved
- The attack chain summary

Format each finding separately with clear evidence.
DO NOT editorialize — just extract the raw findings with evidence.""",
    },
    7: {
        "name": "Ethics + Scope Enforcement",
        "output_subdir": "ethics",
        "focus": "scope boundaries and ethical decisions",
        "extract_prompt": """Extract any mentions of scope, authorization, or ethical boundaries from this writeup.

Include:
1. Any time the author mentioned staying within scope
2. Systems discovered that were NOT targeted and why
3. Decisions to NOT exploit something (and reasoning)
4. Any discussion of responsible disclosure
5. References to rules of engagement
6. Moments where the author chose a less destructive approach
7. Any mention of cleaning up after exploitation

Also note:
- The target scope (what was authorized)
- Any adjacent systems discovered but not exploited
- Ethical considerations mentioned

If the writeup doesn't explicitly discuss ethics/scope, note that.
Many writeups assume scope implicitly — capture any implicit boundaries too.""",
    },
}


# ── Source Detection ────────────────────────────────────────────────────────

def detect_source(url: str) -> str:
    """Detect the writeup source from the URL."""
    domain = urlparse(url).netloc.lower()

    source_map = {
        "0xdf.gitlab.io": "0xdf",
        "rana-khalil.gitbook.io": "rana-khalil",
        "blog.razrsec.uk": "razrsec",
        "medium.com": "medium",
        "infosecwriteups.com": "infosecwriteups",
        "hacktricks.xyz": "hacktricks",
        "book.hacktricks.xyz": "hacktricks",
    }

    for key, source in source_map.items():
        if key in domain:
            return source

    # Fallback: use domain name
    return domain.replace(".", "_")


def extract_box_name(url: str, page_text: str, page_title: str) -> str:
    """Try to extract the box/machine name from URL, title, or content."""

    # Try URL path
    path = urlparse(url).path.lower()

    # 0xdf pattern: /2020/04/07/htb-lame.html
    htb_match = re.search(r"htb-(\w+)", path)
    if htb_match:
        return htb_match.group(1).capitalize()

    # Try page title
    if page_title:
        # Common patterns: "HTB: Lame", "HackTheBox - Lame", "Lame - HTB"
        title_patterns = [
            r"HTB:\s*(\w+)",
            r"HackTheBox\s*[-–]\s*(\w+)",
            r"(\w+)\s*[-–]\s*HTB",
            r"(\w+)\s*[-–]\s*HackTheBox",
            r"(\w+)\s*[-–]\s*Hack\s*The\s*Box",
            r"TryHackMe\s*[-–]\s*(\w+)",
            r"(\w+)\s*[-–]\s*TryHackMe",
            r"VulnHub\s*[-–]\s*(\w+)",
        ]
        for pattern in title_patterns:
            match = re.search(pattern, page_title, re.IGNORECASE)
            if match:
                return match.group(1).capitalize()

    # Fallback: use last meaningful URL segment
    segments = [s for s in path.strip("/").split("/") if s and s != "index.html"]
    if segments:
        name = segments[-1].replace(".html", "").replace(".htm", "").replace("-", "_")
        return name.capitalize()

    return "unknown"


# ── Page Fetching ───────────────────────────────────────────────────────────

def fetch_page(url: str) -> tuple[str, str, str]:
    """
    Fetch a URL and return (raw_text, page_title, error).
    Returns cleaned text content suitable for AI processing.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; ClawStrike-DataPipeline/1.0)"
    }

    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        return "", "", f"Failed to fetch {url}: {e}"

    soup = BeautifulSoup(resp.text, "html.parser")

    # Get title
    title = soup.title.string.strip() if soup.title and soup.title.string else ""

    # Remove unwanted elements
    for tag in soup.find_all(["script", "style", "nav", "footer", "header",
                               "aside", "iframe", "noscript"]):
        tag.decompose()

    # Try to find main content area
    content = None

    # Common content selectors
    selectors = [
        "article",
        ".post-content",
        ".entry-content",
        ".article-content",
        ".content",
        ".markdown-body",
        "main",
        "#content",
        ".post",
    ]

    for selector in selectors:
        found = soup.select_one(selector)
        if found:
            content = found
            break

    if not content:
        content = soup.body if soup.body else soup

    # Extract text preserving code blocks
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

    # If descendants approach got too little, fall back to get_text
    raw_text = "".join(text_parts)
    if len(raw_text.strip()) < 200:
        raw_text = content.get_text(separator="\n", strip=True)

    # Clean up excessive whitespace
    raw_text = re.sub(r"\n{4,}", "\n\n\n", raw_text)

    return raw_text, title, ""


# ── AI-Assisted Extraction ─────────────────────────────────────────────────

def ai_extract(raw_text: str, layer: int, box_name: str, source: str) -> str:
    """
    Use Claude API to extract layer-specific content from raw writeup text.
    Falls back to raw text if API is unavailable.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    if not HAS_ANTHROPIC or not api_key:
        print("  [!] No Anthropic API key — saving raw text (manual extraction needed)")
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


# ── File Output ─────────────────────────────────────────────────────────────

def save_raw_file(content: str, box_name: str, source: str,
                  layer: int, url: str) -> Path:
    """Save extracted content as a raw data file."""

    layer_cfg = LAYER_CONFIG[layer]
    subdir = RAW_DIR / layer_cfg["output_subdir"]
    subdir.mkdir(parents=True, exist_ok=True)

    filename = f"{box_name.lower().replace(' ', '_')}.txt"
    filepath = subdir / filename

    # Build header
    header = f"""{'=' * 75}
HTB: {box_name.upper()} — {layer_cfg['name'].upper()} (Layer {layer})
{'=' * 75}

Box: {box_name}
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
                 layer: int, filepath: Path, status: str):
    """Log extraction metadata for tracking."""
    tracker = META_DIR / "fetch_tracker.jsonl"
    entry = {
        "box_name": box_name,
        "source": source,
        "url": url,
        "layer": layer,
        "output_file": str(filepath),
        "status": status,
        "timestamp": datetime.now().isoformat(),
    }
    with open(tracker, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ── Main Processing ────────────────────────────────────────────────────────

def process_url(url: str, layer: int, use_ai: bool = True) -> bool:
    """Process a single writeup URL."""
    url = url.strip()
    if not url or url.startswith("#"):
        return False

    print(f"\n{'─' * 60}")
    print(f"  URL: {url}")

    # Fetch page
    raw_text, title, error = fetch_page(url)
    if error:
        print(f"  ERROR: {error}")
        log_metadata("unknown", "unknown", url, layer, Path(""), f"FETCH_ERROR: {error}")
        return False

    # Detect source and box name
    source = detect_source(url)
    box_name = extract_box_name(url, raw_text, title)

    print(f"  Box: {box_name}")
    print(f"  Source: {source}")
    print(f"  Layer: {layer} — {LAYER_CONFIG[layer]['name']}")
    print(f"  Content: {len(raw_text.split())} words")

    if len(raw_text.split()) < 100:
        print(f"  WARNING: Very short content — may not extract well")

    # Extract layer-specific content
    if use_ai:
        print(f"  Extracting {LAYER_CONFIG[layer]['focus']}...")
        content = ai_extract(raw_text, layer, box_name, source)
    else:
        content = raw_text

    # Save
    filepath = save_raw_file(content, box_name, source, layer, url)
    log_metadata(box_name, source, url, layer, filepath, "OK")

    print(f"  ✓ Saved → {filepath}")
    return True


def process_links_file(links_file: str, layer: int, use_ai: bool = True):
    """Process all URLs in a links file."""
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
    print(f"  ClawStrike Writeup Fetcher")
    print(f"  Layer {layer}: {layer_cfg['name']}")
    print(f"  URLs to process: {len(urls)}")
    print(f"  AI extraction: {'enabled' if use_ai else 'disabled'}")
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

        # Rate limit — be polite to servers
        if i < len(urls):
            time.sleep(2)

    print(f"\n{'═' * 60}")
    print(f"  Done! {success} succeeded, {failed} failed")
    print(f"  Raw files saved to: {RAW_DIR / layer_cfg['output_subdir']}")
    print(f"  ")
    print(f"  Next step: review the files, then run:")
    print(f"  python scripts/writeup_extractor.py {RAW_DIR / layer_cfg['output_subdir']}/")
    print(f"{'═' * 60}")


# ── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ClawStrike Writeup Fetcher — fetch and format training data from writeup URLs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fetch recon data (Layer 1) from a list of HTB writeup URLs
  python scripts/writeup_fetcher.py links/htb_boxes.txt --layer 1

  # Fetch failure/pivot data (Layer 3)
  python scripts/writeup_fetcher.py links/htb_boxes.txt --layer 3

  # Fetch without AI extraction (just raw page content)
  python scripts/writeup_fetcher.py links/htb_boxes.txt --layer 1 --no-ai

  # Quick single URL test
  echo "https://0xdf.gitlab.io/2020/04/07/htb-lame.html" > /tmp/test.txt
  python scripts/writeup_fetcher.py /tmp/test.txt --layer 1

Workflow for juniors:
  1. Create a text file with one writeup URL per line
  2. Run this script with the appropriate --layer flag
  3. Hand the output files to the lead for review
  4. Lead runs writeup_extractor.py on approved files
""",
    )

    parser.add_argument("links_file", help="Text file containing one URL per line")
    parser.add_argument("--layer", type=int, default=1, choices=range(1, 8),
                        help="Training data layer (1-7, default: 1)")
    parser.add_argument("--no-ai", action="store_true",
                        help="Skip AI extraction — save raw page text only")

    args = parser.parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY") and not args.no_ai:
        print("WARNING: ANTHROPIC_API_KEY not set. AI extraction will be skipped.")
        print("Set it with: export ANTHROPIC_API_KEY=your_key_here\n")

    process_links_file(args.links_file, args.layer, use_ai=not args.no_ai)


if __name__ == "__main__":
    main()
