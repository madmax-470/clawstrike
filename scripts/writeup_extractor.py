"""
Writeup Extractor — Uses Claude API to extract structured training data
from raw HTB/THM writeup text.

Workflow:
1. Copy a writeup's recon/enumeration section into a text file
2. Run this script pointing to that file
3. Claude extracts the structured box dict
4. You review and approve
5. It feeds into layer1_converter automatically
"""

import json
import os
import sys
from pathlib import Path
from anthropic import Anthropic

sys.path.insert(0, str(Path(__file__).parent))
from layer1_converter import build_example, save_examples

client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

RAW_DIR = Path.home() / "clawstrike-data" / "raw"

EXTRACTION_PROMPT = """You are a training data extraction tool for an offensive security AI.

Given a penetration testing writeup, extract the following structured data as a JSON object:

{
  "box_name": "name of the box/machine",
  "target": "IP address used in the writeup",
  "source": "author or blog name",
  "difficulty": "easy/medium/hard/insane",
  
  "ports": [
    {"port": 21, "proto": "tcp", "service": "FTP", "version": "vsftpd 2.3.4"}
  ],
  
  "priorities": [
    {
      "service": "service name + version",
      "reasoning": "why this should be investigated first/next — based on exploit probability"
    }
  ],
  
  "first_action": "the exact first thing the tester did after seeing the scan",
  "fallback": "what they would do if the first action failed",
  "avoid": "what should NOT be tried at this stage and why",
  
  "pivot_point": {
    "result": "what the first action returned",
    "reasoning": "why they decided to change approach or continue",
    "next_action": "what they did next",
    "fallback": "backup plan if this also fails"
  },
  
  "failed_attempt": {
    "action": "something that was tried and failed",
    "result": "what happened when it failed",
    "reasoning": "why it failed and what that teaches us",
    "next_action": "what they pivoted to"
  }
}

RULES:
- Extract REAL reasoning from the writeup, do not invent
- If the writeup doesn't mention a failed attempt, set failed_attempt to null
- If there's no clear pivot point, set pivot_point to null
- The priorities should reflect actual pentest logic, not just port order
- Include version numbers whenever available
- The reasoning must explain WHY, not just WHAT

Return ONLY the JSON object, no markdown, no backticks, no explanation."""


def extract_from_writeup(writeup_text: str) -> dict | None:
    """Send writeup text to Claude, get structured box dict back."""

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        messages=[
            {
                "role": "user",
                "content": f"{EXTRACTION_PROMPT}\n\n--- WRITEUP TEXT ---\n\n{writeup_text}"
            }
        ]
    )

    raw = response.content[0].text.strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Try to extract JSON from response if wrapped in anything
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start != -1 and end > start:
            try:
                return json.loads(raw[start:end])
            except json.JSONDecodeError:
                pass
        print(f"ERROR: Could not parse Claude response as JSON")
        print(f"Raw response:\n{raw[:500]}")
        return None


def review_and_confirm(box_data: dict) -> bool:
    """Show extracted data to user for review."""
    print("\n" + "=" * 60)
    print(f"Box: {box_data.get('box_name', 'unknown')}")
    print(f"Target: {box_data.get('target', 'unknown')}")
    print(f"Source: {box_data.get('source', 'unknown')}")
    print(f"Difficulty: {box_data.get('difficulty', 'unknown')}")
    print(f"\nPorts found: {len(box_data.get('ports', []))}")

    for p in box_data.get("ports", []):
        print(f"  - {p['port']}/{p['proto']} {p['service']} {p.get('version', '?')}")

    print(f"\nPriorities:")
    for i, pr in enumerate(box_data.get("priorities", []), 1):
        print(f"  {i}. {pr['service']}")
        print(f"     → {pr['reasoning'][:100]}...")

    print(f"\nFirst action: {box_data.get('first_action', '?')}")
    print(f"Fallback: {box_data.get('fallback', 'none')}")
    print(f"Avoid: {box_data.get('avoid', 'none')}")

    has_pivot = box_data.get("pivot_point") is not None
    has_fail = box_data.get("failed_attempt") is not None
    print(f"\nPivot point: {'yes' if has_pivot else 'no'}")
    print(f"Failed attempt: {'yes' if has_fail else 'no'}")
    print("=" * 60)

    while True:
        choice = input("\n[a]pprove / [e]dit manually / [s]kip → ").strip().lower()
        if choice in ("a", "e", "s"):
            return choice
        print("Enter a, e, or s")


def process_file(filepath: str):
    """Process a single writeup file."""
    path = Path(filepath)

    if not path.exists():
        print(f"File not found: {filepath}")
        return

    writeup_text = path.read_text()
    word_count = len(writeup_text.split())
    print(f"\nLoaded: {path.name} ({word_count} words)")

    if word_count < 50:
        print("WARNING: Very short writeup. May not extract well.")

    print("Sending to Claude for extraction...")
    box_data = extract_from_writeup(writeup_text)

    if not box_data:
        print("Extraction failed. Check the writeup format.")
        return

    choice = review_and_confirm(box_data)

    if choice == "s":
        print("Skipped.")
        return

    if choice == "e":
        # Save raw extraction for manual editing
        edit_path = Path.home() / "clawstrike-data" / "raw" / f"{box_data.get('box_name', 'unknown').lower()}_extracted.json"
        with open(edit_path, "w") as f:
            json.dump(box_data, f, indent=2)
        print(f"Saved for editing → {edit_path}")
        print("Edit the file, then run:")
        print(f"  python scripts/load_edited.py {edit_path}")
        return

    # Approved — generate training examples
    examples = build_example(box_data)
    save_examples(examples, box_data.get("box_name", "unknown"))
    print(f"\n✓ {len(examples)} training examples generated and saved.")


def process_directory(dirpath: str):
    """Process all .txt/.md files in a directory."""
    path = Path(dirpath)
    files = sorted(path.glob("*.txt")) + sorted(path.glob("*.md"))

    if not files:
        print(f"No .txt or .md files found in {dirpath}")
        return

    print(f"Found {len(files)} writeup files\n")

    for f in files:
        print(f"\n{'─' * 40}")
        process_file(str(f))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Single file:    python writeup_extractor.py path/to/writeup.txt")
        print("  Directory:      python writeup_extractor.py path/to/writeups/")
        print()
        print("Workflow:")
        print("  1. Copy a writeup's recon section into a .txt file")
        print("  2. Save it in ~/clawstrike-data/raw/htb/")
        print("  3. Run this script on it")
        print("  4. Review and approve the extracted data")
        sys.exit(1)

    target = sys.argv[1]

    if Path(target).is_dir():
        process_directory(target)
    else:
        process_file(target)
