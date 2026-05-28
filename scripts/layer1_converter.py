"""
Layer 1 Converter — Recon Decision Trees
Takes structured input about a box/engagement and outputs training JSONL.
This is a manual-assisted tool, not a blind scraper.

Workflow:
1. You read a writeup
2. You fill in the template below
3. This script converts it to proper training format
4. Output goes to processed/layer1_recon/
"""

import json
import os
from datetime import datetime
from pathlib import Path

OUTPUT_DIR = Path.home() / "clawstrike-data" / "processed" / "layer1_recon"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

METADATA_DIR = Path.home() / "clawstrike-data" / "metadata"
METADATA_DIR.mkdir(parents=True, exist_ok=True)


def build_example(box: dict) -> list[dict]:
    """
    Takes a box dict and produces one or more training examples.
    Each example = one decision point the model needs to learn.
    """
    examples = []

    # --- Example 1: Initial scan → first decision ---
    ports_text = "\n".join(
        f"- {p['port']}/{p['proto']} {p['service']} {p.get('version', 'unknown')}"
        for p in box["ports"]
    )

    instruction = (
        f"You are a penetration tester conducting authorized testing.\n"
        f"Analyze the following scan output and decide the next action.\n\n"
        f"Target: {box['target']}\n"
        f"Open ports:\n{ports_text}"
    )

    # Build the reasoning output
    reasoning_lines = ["Thought: Analyzing discovered services by exploit probability.\n"]

    for i, priority in enumerate(box["priorities"], 1):
        reasoning_lines.append(
            f"{i}. {priority['service']} — {priority['reasoning']}"
        )

    reasoning_lines.append(f"\nAction: {box['first_action']}")

    if box.get("fallback"):
        reasoning_lines.append(f"Fallback: {box['fallback']}")

    if box.get("avoid"):
        reasoning_lines.append(f"Do NOT attempt: {box['avoid']}")

    output = "\n".join(reasoning_lines)

    examples.append({
        "instruction": instruction,
        "output": output,
        "metadata": {
            "layer": "layer1_recon",
            "source": box.get("source", "unknown"),
            "box_name": box.get("box_name", "unknown"),
            "difficulty": box.get("difficulty", "unknown"),
            "created": datetime.now().isoformat(),
        }
    })

    # --- Example 2: After first tool runs → next decision ---
    if box.get("pivot_point"):
        pivot = box["pivot_point"]

        instruction2 = (
            f"You are a penetration tester conducting authorized testing.\n"
            f"Your previous action returned the following result.\n\n"
            f"Target: {box['target']}\n"
            f"Previous action: {box['first_action']}\n"
            f"Result:\n{pivot['result']}"
        )

        output2 = (
            f"Thought: {pivot['reasoning']}\n\n"
            f"Action: {pivot['next_action']}"
        )

        if pivot.get("fallback"):
            output2 += f"\nFallback: {pivot['fallback']}"

        examples.append({
            "instruction": instruction2,
            "output": output2,
            "metadata": {
                "layer": "layer1_recon",
                "source": box.get("source", "unknown"),
                "box_name": box.get("box_name", "unknown"),
                "type": "pivot_decision",
                "created": datetime.now().isoformat(),
            }
        })

    # --- Example 3: Failed path (Layer 1 + Layer 3 crossover) ---
    if box.get("failed_attempt"):
        fail = box["failed_attempt"]

        instruction3 = (
            f"You are a penetration tester conducting authorized testing.\n"
            f"Your action did not succeed. Decide what to do next.\n\n"
            f"Target: {box['target']}\n"
            f"Action attempted: {fail['action']}\n"
            f"Result: {fail['result']}"
        )

        output3 = (
            f"Thought: {fail['reasoning']}\n\n"
            f"Action: {fail['next_action']}"
        )

        examples.append({
            "instruction": instruction3,
            "output": output3,
            "metadata": {
                "layer": "layer1_recon",
                "source": box.get("source", "unknown"),
                "box_name": box.get("box_name", "unknown"),
                "type": "failure_recovery",
                "created": datetime.now().isoformat(),
            }
        })

    return examples


def save_examples(examples: list[dict], box_name: str):
    """Save examples as JSONL."""
    filename = f"{box_name.lower().replace(' ', '_')}.jsonl"
    filepath = OUTPUT_DIR / filename

    with open(filepath, "a") as f:
        for ex in examples:
            f.write(json.dumps(ex) + "\n")

    print(f"✓ {len(examples)} examples saved → {filepath}")

    # Update metadata tracker
    tracker_path = METADATA_DIR / "layer1_tracker.jsonl"
    with open(tracker_path, "a") as f:
        f.write(json.dumps({
            "box_name": box_name,
            "examples_count": len(examples),
            "source": examples[0]["metadata"]["source"],
            "created": datetime.now().isoformat(),
        }) + "\n")


# ──────────────────────────────────────────────────────────────
# TEMPLATE — Fill this in for each box you read a writeup for
# ──────────────────────────────────────────────────────────────

LAME = {
    "box_name": "Lame",
    "target": "10.10.10.3",
    "source": "0xdf HTB writeup",
    "difficulty": "easy",

    "ports": [
        {"port": 21, "proto": "tcp", "service": "FTP", "version": "vsftpd 2.3.4"},
        {"port": 22, "proto": "tcp", "service": "SSH", "version": "OpenSSH 4.7p1"},
        {"port": 139, "proto": "tcp", "service": "NetBIOS", "version": "Samba 3.0.20"},
        {"port": 445, "proto": "tcp", "service": "SMB", "version": "Samba 3.0.20"},
    ],

    "priorities": [
        {
            "service": "FTP vsftpd 2.3.4",
            "reasoning": "Known backdoor vulnerability CVE-2011-2523. Highest priority — check if backdoor is triggerable."
        },
        {
            "service": "SMB Samba 3.0.20",
            "reasoning": "Old version vulnerable to username map script RCE (CVE-2007-2447). Strong fallback if FTP fails."
        },
        {
            "service": "SSH OpenSSH 4.7p1",
            "reasoning": "Old but rarely directly exploitable without credentials. Lowest priority for now."
        },
    ],

    "first_action": "searchsploit vsftpd 2.3.4",
    "fallback": "If vsftpd backdoor fails or is patched, pivot to Samba 3.0.20 username map script exploit.",
    "avoid": "SSH brute force at this stage — noisy, slow, and no username list available.",

    "pivot_point": {
        "result": "vsftpd 2.3.4 backdoor — exploit found but connection hangs. Backdoor appears patched or filtered.",
        "reasoning": "FTP backdoor is not working. Samba 3.0.20 is the next highest priority. The username map script vulnerability allows RCE through a crafted username.",
        "next_action": "searchsploit samba 3.0.20",
        "fallback": "If Samba exploit fails, enumerate SMB shares anonymously with smbclient -L.",
    },

    "failed_attempt": {
        "action": "Attempted vsftpd 2.3.4 backdoor exploit",
        "result": "Connection to backdoor port 6200 timed out. Backdoor trigger sent but no shell returned.",
        "reasoning": "The vsftpd backdoor is likely patched in this instance or a firewall is blocking port 6200. This is a known issue with this exploit — the backdoor exists in the source but may not always be functional. Moving to next attack vector.",
        "next_action": "Use Metasploit module exploit/multi/samba/usermap_script against SMB on port 445.",
    },
}


if __name__ == "__main__":
    # Process the example box
    examples = build_example(LAME)
    save_examples(examples, LAME["box_name"])

    print(f"\nTotal examples generated: {len(examples)}")
    print(f"Output directory: {OUTPUT_DIR}")
    print("\nTo add more boxes, copy the LAME template and fill in new data.")
