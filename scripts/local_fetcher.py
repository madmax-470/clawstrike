"""
Local file processor — same as fetcher but for local files.
Adds header, runs AI extraction, saves to raw/{platform}/layer{N}/

Usage:
  python scripts/local_fetcher.py <file_or_dir> --layer N --platform htb
"""

import argparse
import os
import re
import sys
from pathlib import Path
from datetime import datetime

try:
    from anthropic import Anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

sys.path.insert(0, str(Path(__file__).parent))
from writeup_fetcher import LAYER_CONFIG, LAYER_NAMES, save_raw_file, log_metadata, ai_extract

RAW_DIR = Path.home() / "clawstrike-data" / "raw"


def extract_name_from_file(filepath: Path) -> str:
    name = filepath.stem
    name = re.sub(r"^\d{4}-\d{2}-\d{2}-?", "", name)
    name = re.sub(r"^(transcript|ippsec|writeup)[_-]?", "", name, flags=re.IGNORECASE)
    name = name.replace("-", "_").replace("_", " ").strip()
    return name.capitalize() if name else "Unknown"


def process_local_file(filepath: Path, layer: int, platform: str, use_ai: bool = True):
    text = filepath.read_text(errors="replace")
    words = len(text.split())
    box_name = extract_name_from_file(filepath)

    print(f"\n{'─' * 60}")
    print(f"  File: {filepath.name}")
    print(f"  Box: {box_name}")
    print(f"  Platform: {platform}")
    print(f"  Layer: {layer} — {LAYER_CONFIG[layer]['name']}")
    print(f"  Content: {words} words")
    print(f"  Saving to: raw/{platform}/layer{layer}/")

    if use_ai:
        print(f"  Extracting {LAYER_CONFIG[layer]['focus']}...")
        content = ai_extract(text, layer, box_name, "ippsec")
    else:
        content = text

    out = save_raw_file(content, box_name, "ippsec", platform, layer, f"local://{filepath}")
    log_metadata(box_name, "ippsec", f"local://{filepath}", platform, layer, out, "OK")
    print(f"  ✓ Saved → {out}")


def main():
    parser = argparse.ArgumentParser(description="Process local transcript/writeup files")
    parser.add_argument("path", help="File or directory")
    parser.add_argument("--layer", type=int, default=1, choices=range(1, 8))
    parser.add_argument("--platform", default="htb", choices=["htb", "vulnhub", "thm", "other"])
    parser.add_argument("--no-ai", action="store_true")
    args = parser.parse_args()

    path = Path(args.path)
    if path.is_file():
        process_local_file(path, args.layer, args.platform, not args.no_ai)
    elif path.is_dir():
        files = sorted(path.glob("*.txt")) + sorted(path.glob("*.md"))
        print(f"Found {len(files)} files")
        for f in files:
            process_local_file(f, args.layer, args.platform, not args.no_ai)
    else:
        print(f"Not found: {path}")

if __name__ == "__main__":
    main()
