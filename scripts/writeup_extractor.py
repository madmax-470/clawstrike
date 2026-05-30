"""
ClawStrike — Writeup Extractor (v2)
=====================================
Takes raw writeup text files and uses Claude API to extract structured
training data. Presents the extraction for human review before saving.

Now layer-aware — saves to processed/{layer_name}/ automatically.

Usage:
  python scripts/writeup_extractor.py <path> [--layer N]

Examples:
  python scripts/writeup_extractor.py raw/vulnhub/layer1/ --layer 1
  python scripts/writeup_extractor.py raw/htb/layer2/ --layer 2
  python scripts/writeup_extractor.py raw/vulnhub/layer3/dc6.txt --layer 3
"""

import json
import os
import sys
import re
import argparse
from pathlib import Path
from datetime import datetime

try:
    from anthropic import Anthropic
except ImportError:
    print("ERROR: pip install anthropic")
    sys.exit(1)

PROCESSED_DIR = Path.home() / "clawstrike-data" / "processed"
METADATA_DIR = Path.home() / "clawstrike-data" / "metadata"
RAW_DIR = Path.home() / "clawstrike-data" / "raw"

for d in [PROCESSED_DIR, METADATA_DIR]:
    d.mkdir(parents=True, exist_ok=True)

LAYER_OUTPUT_DIRS = {
    1: "layer1_recon",
    2: "layer2_parsing",
    3: "layer3_failures",
    4: "layer4_exploits",
    5: "layer5_postexploit",
    6: "layer6_reporting",
    7: "layer7_ethics",
}

LAYER_NAMES = {
    1: "Recon Decision Trees",
    2: "Tool Output Parsing",
    3: "Failed Paths + Pivots",
    4: "Exploit Ranking",
    5: "Post-Exploitation Reasoning",
    6: "Reporting Intelligence",
    7: "Ethics + Scope Enforcement",
}

# ── Extraction Prompts Per Layer ────────────────────────────────────────────

EXTRACTION_PROMPTS = {
    1: """Given a penetration testing writeup, extract the following structured data as a JSON object:

{
  "box_name": "name of the box/machine",
  "target": "IP address used",
  "source": "author or blog name",
  "difficulty": "easy/medium/hard/insane",

  "ports": [
    {"port": 21, "proto": "tcp", "service": "FTP", "version": "vsftpd 2.3.4"}
  ],

  "priorities": [
    {
      "service": "service name + version",
      "reasoning": "why this should be investigated first/next"
    }
  ],

  "first_action": "the first thing the tester did after seeing the scan",
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
- If no failed attempt, set failed_attempt to null
- If no pivot point, set pivot_point to null
- Include version numbers whenever available
- The reasoning must explain WHY, not just WHAT
- Return ONLY the JSON object, no markdown, no backticks""",

    2: """Given a penetration testing writeup, extract tool outputs as a JSON object:

{
  "box_name": "name of the box",
  "source": "author or blog",
  "difficulty": "easy/medium/hard",

  "tool_outputs": [
    {
      "tool": "nmap",
      "command": "nmap -sV -sC 10.10.10.3",
      "raw_output": "the actual output text",
      "findings": [
        {
          "finding": "what was discovered",
          "severity": "CRITICAL/HIGH/MEDIUM/LOW/INFO",
          "reasoning": "why this matters"
        }
      ],
      "noise_filtered": "what was irrelevant in the output",
      "next_step": "what to do based on this output",
      "next_step_reasoning": "why that next step makes sense"
    }
  ]
}

RULES:
- Include the actual raw tool output, not a summary
- Each finding needs a severity and reasoning
- Identify what is noise vs signal
- Return ONLY the JSON object""",

    3: """Given a penetration testing writeup, extract failed attempts as a JSON object:

{
  "box_name": "name of the box",
  "source": "author or blog",
  "difficulty": "easy/medium/hard",

  "failures": [
    {
      "action": "what was attempted",
      "command": "exact command if available",
      "expected": "what they expected to happen",
      "result": "what actually happened",
      "error_output": "error message if any",
      "reasoning": "why it failed",
      "recovery": "what they did next",
      "recovery_reasoning": "why they chose that recovery path",
      "lesson": "what this teaches about pentesting"
    }
  ]
}

RULES:
- Focus ONLY on things that failed or didn't work as expected
- Include the reasoning about WHY it failed
- Include what they learned from the failure
- Return ONLY the JSON object""",

    4: """Given a penetration testing writeup, extract exploit ranking as a JSON object:

{
  "box_name": "name of the box",
  "source": "author or blog",
  "difficulty": "easy/medium/hard",

  "vulnerabilities_found": [
    {
      "service": "service name and version",
      "vulnerability": "what the vulnerability is",
      "cve": "CVE number if mentioned",
      "exploit_probability": "HIGH/MEDIUM/LOW",
      "impact": "CRITICAL/HIGH/MEDIUM/LOW",
      "reasoning": "why this ranking",
      "exploit_method": "how it would be exploited",
      "reliability": "how reliable the exploit is"
    }
  ],

  "chosen_path": "which vulnerability they exploited first",
  "chosen_reasoning": "why they chose this path over others",
  "alternative_paths": "what else they could have tried"
}

RULES:
- Focus on the RANKING LOGIC, not exploit details
- Explain why one path was chosen over another
- Return ONLY the JSON object""",

    5: """Given a penetration testing writeup, extract post-exploitation as a JSON object:

{
  "box_name": "name of the box",
  "source": "author or blog",
  "difficulty": "easy/medium/hard",

  "initial_access": {
    "user": "username of the shell",
    "privilege_level": "low/medium/high",
    "os": "operating system",
    "kernel": "kernel version if mentioned"
  },

  "enumeration_steps": [
    {
      "command": "command run",
      "purpose": "why they ran this",
      "output_summary": "key findings from the output",
      "led_to": "what this finding led to next"
    }
  ],

  "privesc_vector": {
    "type": "SUID/sudo/kernel/cron/credentials/misconfiguration",
    "description": "what the vulnerability was",
    "reasoning": "why they chose this vector",
    "command": "how they exploited it"
  },

  "failed_privesc": [
    {
      "attempt": "what they tried",
      "result": "why it didn't work"
    }
  ],

  "credentials_found": ["any credentials harvested"],
  "lateral_movement": "any lateral movement attempted"
}

RULES:
- Start from initial shell, not from exploitation
- Focus on reasoning for each enumeration step
- Include failed privesc attempts
- Return ONLY the JSON object""",

    6: """Given a penetration testing writeup, extract reporting data as a JSON object:

{
  "box_name": "name of the box",
  "source": "author or blog",

  "findings": [
    {
      "title": "professional finding title",
      "severity": "CRITICAL/HIGH/MEDIUM/LOW/INFO",
      "service": "affected service and version",
      "description": "what the vulnerability is",
      "impact": "business impact of exploitation",
      "evidence": "commands and outputs proving the vulnerability",
      "remediation": "how to fix it",
      "cve": "CVE reference if applicable"
    }
  ],

  "attack_chain_summary": "how the full compromise worked step by step"
}

RULES:
- Write findings in professional report language
- Include concrete remediation steps
- Evidence must prove the finding
- Return ONLY the JSON object""",

    7: """Given a penetration testing writeup, extract ethics/scope data as a JSON object:

{
  "box_name": "name of the box",
  "source": "author or blog",

  "scope_decisions": [
    {
      "situation": "what happened",
      "decision": "what they decided to do or not do",
      "reasoning": "why they made that decision",
      "correct_action": "the professionally correct response"
    }
  ],

  "out_of_scope_discoveries": [
    {
      "discovery": "what was found",
      "action_taken": "documented but not exploited",
      "reasoning": "why it was left alone"
    }
  ]
}

RULES:
- If the writeup has no explicit scope/ethics discussion, construct reasonable scope boundaries
- Return ONLY the JSON object""",
}


# ── Layer-Specific Converters ───────────────────────────────────────────────

def convert_layer1(data: dict) -> list[dict]:
    """Convert Layer 1 extraction to training examples."""
    examples = []

    ports_text = "\n".join(
        f"- {p['port']}/{p['proto']} {p['service']} {p.get('version', 'unknown')}"
        for p in data.get("ports", [])
    )

    if not ports_text:
        return examples

    instruction = (
        f"You are a penetration tester conducting authorized testing.\n"
        f"Analyze the following scan output and decide the next action.\n\n"
        f"Target: {data.get('target', 'unknown')}\n"
        f"Open ports:\n{ports_text}"
    )

    reasoning_lines = ["Thought: Analyzing discovered services by exploit probability.\n"]
    for i, p in enumerate(data.get("priorities", []), 1):
        reasoning_lines.append(f"{i}. {p['service']} — {p['reasoning']}")

    reasoning_lines.append(f"\nAction: {data.get('first_action', 'enumerate further')}")
    if data.get("fallback"):
        reasoning_lines.append(f"Fallback: {data['fallback']}")
    if data.get("avoid"):
        reasoning_lines.append(f"Do NOT attempt: {data['avoid']}")

    examples.append({
        "instruction": instruction,
        "output": "\n".join(reasoning_lines),
        "metadata": {
            "layer": "layer1_recon",
            "source": data.get("source", "unknown"),
            "box_name": data.get("box_name", "unknown"),
            "difficulty": data.get("difficulty", "unknown"),
            "created": datetime.now().isoformat(),
        }
    })

    if data.get("pivot_point"):
        pivot = data["pivot_point"]
        instr2 = (
            f"You are a penetration tester conducting authorized testing.\n"
            f"Your previous action returned the following result.\n\n"
            f"Target: {data.get('target', 'unknown')}\n"
            f"Previous action: {data.get('first_action', 'unknown')}\n"
            f"Result:\n{pivot.get('result', '')}"
        )
        out2 = f"Thought: {pivot.get('reasoning', '')}\n\nAction: {pivot.get('next_action', '')}"
        if pivot.get("fallback"):
            out2 += f"\nFallback: {pivot['fallback']}"

        examples.append({
            "instruction": instr2,
            "output": out2,
            "metadata": {
                "layer": "layer1_recon", "source": data.get("source", "unknown"),
                "box_name": data.get("box_name", "unknown"), "type": "pivot_decision",
                "created": datetime.now().isoformat(),
            }
        })

    if data.get("failed_attempt"):
        fail = data["failed_attempt"]
        instr3 = (
            f"You are a penetration tester conducting authorized testing.\n"
            f"Your action did not succeed. Decide what to do next.\n\n"
            f"Target: {data.get('target', 'unknown')}\n"
            f"Action attempted: {fail.get('action', '')}\n"
            f"Result: {fail.get('result', '')}"
        )
        out3 = f"Thought: {fail.get('reasoning', '')}\n\nAction: {fail.get('next_action', '')}"

        examples.append({
            "instruction": instr3,
            "output": out3,
            "metadata": {
                "layer": "layer1_recon", "source": data.get("source", "unknown"),
                "box_name": data.get("box_name", "unknown"), "type": "failure_recovery",
                "created": datetime.now().isoformat(),
            }
        })

    return examples


def convert_layer2(data: dict) -> list[dict]:
    """Convert Layer 2 extraction to training examples."""
    examples = []

    for tool_entry in data.get("tool_outputs", []):
        instruction = (
            f"You are a penetration tester conducting authorized testing.\n"
            f"Parse the following {tool_entry['tool']} output and extract key findings.\n\n"
            f"Command: {tool_entry.get('command', 'unknown')}\n\n"
            f"Raw output:\n{tool_entry.get('raw_output', '')}"
        )

        findings_text = []
        for i, f in enumerate(tool_entry.get("findings", []), 1):
            findings_text.append(
                f"{i}. [{f.get('severity', 'INFO')}] {f.get('finding', '')}\n"
                f"   → {f.get('reasoning', '')}"
            )

        output_parts = ["Findings:\n", "\n\n".join(findings_text)]
        if tool_entry.get("noise_filtered"):
            output_parts.append(f"\n\nNoise filtered: {tool_entry['noise_filtered']}")
        output_parts.append(f"\n\nRecommended next step: {tool_entry.get('next_step', '')}")
        if tool_entry.get("next_step_reasoning"):
            output_parts.append(f"Reasoning: {tool_entry['next_step_reasoning']}")

        examples.append({
            "instruction": instruction,
            "output": "\n".join(output_parts),
            "metadata": {
                "layer": "layer2_parsing", "source": data.get("source", "unknown"),
                "box_name": data.get("box_name", "unknown"),
                "tool": tool_entry["tool"], "type": "output_parsing",
                "created": datetime.now().isoformat(),
            }
        })

    return examples


def convert_layer3(data: dict) -> list[dict]:
    """Convert Layer 3 extraction to training examples."""
    examples = []

    for failure in data.get("failures", []):
        instruction = (
            f"You are a penetration tester conducting authorized testing.\n"
            f"Your action did not succeed. Decide what to do next.\n\n"
            f"Target: {data.get('target', 'unknown')}\n"
            f"Action attempted: {failure.get('action', '')}\n"
            f"Expected: {failure.get('expected', 'successful execution')}\n"
            f"Result: {failure.get('result', '')}"
        )

        if failure.get("error_output"):
            instruction += f"\nError output:\n{failure['error_output']}"

        output = (
            f"Thought: {failure.get('reasoning', '')}\n\n"
            f"Lesson: {failure.get('lesson', '')}\n\n"
            f"Action: {failure.get('recovery', '')}\n"
            f"Reasoning: {failure.get('recovery_reasoning', '')}"
        )

        examples.append({
            "instruction": instruction,
            "output": output,
            "metadata": {
                "layer": "layer3_failures", "source": data.get("source", "unknown"),
                "box_name": data.get("box_name", "unknown"), "type": "failure_recovery",
                "created": datetime.now().isoformat(),
            }
        })

    return examples


def convert_layer4(data: dict) -> list[dict]:
    """Convert Layer 4 extraction to training examples."""
    examples = []

    vulns = data.get("vulnerabilities_found", [])
    if not vulns:
        return examples

    vuln_text = "\n".join(
        f"- {v['service']}: {v['vulnerability']}" for v in vulns
    )

    instruction = (
        f"You are a penetration tester conducting authorized testing.\n"
        f"Based on enumeration results, rank the exploit paths for this target.\n\n"
        f"Target: {data.get('target', 'unknown')}\n"
        f"Findings:\n{vuln_text}"
    )

    ranking_lines = ["Exploit ranking by probability and impact:\n"]
    for i, v in enumerate(vulns, 1):
        prob = v.get("exploit_probability", "UNKNOWN")
        impact = v.get("impact", "UNKNOWN")
        ranking_lines.append(
            f"{i}. [{prob} PROB / {impact} IMPACT] {v.get('vulnerability', '')}\n"
            f"   Service: {v.get('service', '')}\n"
            f"   Reasoning: {v.get('reasoning', '')}\n"
            f"   Reliability: {v.get('reliability', 'unknown')}"
        )

    ranking_lines.append(f"\nChosen path: {data.get('chosen_path', '')}")
    ranking_lines.append(f"Reasoning: {data.get('chosen_reasoning', '')}")
    if data.get("alternative_paths"):
        ranking_lines.append(f"Alternatives: {data['alternative_paths']}")

    examples.append({
        "instruction": instruction,
        "output": "\n\n".join(ranking_lines),
        "metadata": {
            "layer": "layer4_exploits", "source": data.get("source", "unknown"),
            "box_name": data.get("box_name", "unknown"), "type": "exploit_ranking",
            "created": datetime.now().isoformat(),
        }
    })

    return examples


def convert_layer5(data: dict) -> list[dict]:
    """Convert Layer 5 extraction to training examples."""
    examples = []

    initial = data.get("initial_access", {})
    steps = data.get("enumeration_steps", [])
    privesc = data.get("privesc_vector", {})

    if not initial or not privesc:
        return examples

    steps_text = "\n".join(
        f"- {s.get('command', '?')} → {s.get('output_summary', '?')}"
        for s in steps[:5]
    )

    instruction = (
        f"You are a penetration tester conducting authorized testing.\n"
        f"You have gained a low-privilege shell on the target. "
        f"Decide your post-exploitation priorities.\n\n"
        f"Target: {data.get('target', 'unknown')}\n"
        f"Access: shell as '{initial.get('user', 'unknown')}'\n"
        f"OS: {initial.get('os', 'unknown')}\n"
        f"Kernel: {initial.get('kernel', 'unknown')}"
    )

    output_parts = [
        f"Thought: Assessing privilege escalation options from {initial.get('user', 'unknown')} shell.\n"
    ]

    for s in steps:
        output_parts.append(
            f"Check: {s.get('command', '?')}\n"
            f"Purpose: {s.get('purpose', '?')}\n"
            f"Result: {s.get('output_summary', '?')}"
        )

    output_parts.append(
        f"\nPrivilege escalation vector: {privesc.get('type', 'unknown')}\n"
        f"Description: {privesc.get('description', '')}\n"
        f"Reasoning: {privesc.get('reasoning', '')}\n"
        f"Command: {privesc.get('command', '')}"
    )

    failed = data.get("failed_privesc", [])
    if failed:
        output_parts.append("\nFailed attempts:")
        for f in failed:
            output_parts.append(f"- {f.get('attempt', '?')} → {f.get('result', '?')}")

    examples.append({
        "instruction": instruction,
        "output": "\n\n".join(output_parts),
        "metadata": {
            "layer": "layer5_postexploit", "source": data.get("source", "unknown"),
            "box_name": data.get("box_name", "unknown"), "type": "privesc_reasoning",
            "created": datetime.now().isoformat(),
        }
    })

    return examples


def convert_layer6(data: dict) -> list[dict]:
    """Convert Layer 6 extraction to training examples."""
    examples = []

    for finding in data.get("findings", []):
        evidence = finding.get("evidence", "")
        if isinstance(evidence, list):
            evidence = "\n".join(evidence)

        instruction = (
            f"You are a penetration tester conducting authorized testing.\n"
            f"Convert the following evidence into a professional vulnerability finding.\n\n"
            f"Evidence:\n{evidence}"
        )

        output = (
            f"Finding Title: {finding.get('title', '')}\n\n"
            f"Severity: {finding.get('severity', 'MEDIUM')}\n\n"
            f"Description:\n{finding.get('description', '')}\n\n"
            f"Impact:\n{finding.get('impact', '')}\n\n"
            f"Evidence Summary:\n{evidence}\n\n"
            f"Remediation:\n{finding.get('remediation', '')}"
        )

        if finding.get("cve"):
            output += f"\n\nCVE Reference: {finding['cve']}"

        examples.append({
            "instruction": instruction,
            "output": output,
            "metadata": {
                "layer": "layer6_reporting", "source": data.get("source", "unknown"),
                "box_name": data.get("box_name", "unknown"), "type": "finding_report",
                "created": datetime.now().isoformat(),
            }
        })

    return examples


def convert_layer7(data: dict) -> list[dict]:
    """Convert Layer 7 extraction to training examples."""
    examples = []

    for decision in data.get("scope_decisions", []):
        instruction = (
            f"You are a penetration tester conducting authorized testing.\n"
            f"Evaluate the following situation and decide the correct action.\n\n"
            f"Situation: {decision.get('situation', '')}"
        )

        output = (
            f"Decision: {decision.get('decision', '')}\n\n"
            f"Reasoning: {decision.get('reasoning', '')}\n\n"
            f"Correct professional action: {decision.get('correct_action', '')}"
        )

        examples.append({
            "instruction": instruction,
            "output": output,
            "metadata": {
                "layer": "layer7_ethics", "source": data.get("source", "unknown"),
                "box_name": data.get("box_name", "unknown"), "type": "scope_decision",
                "created": datetime.now().isoformat(),
            }
        })

    for discovery in data.get("out_of_scope_discoveries", []):
        instruction = (
            f"You are a penetration tester conducting authorized testing.\n"
            f"During enumeration, you discovered something outside your authorized scope.\n\n"
            f"Discovery: {discovery.get('discovery', '')}"
        )

        output = (
            f"STOP — Scope boundary reached.\n\n"
            f"Action taken: {discovery.get('action_taken', 'Document but do not exploit')}\n\n"
            f"Reasoning: {discovery.get('reasoning', '')}"
        )

        examples.append({
            "instruction": instruction,
            "output": output,
            "metadata": {
                "layer": "layer7_ethics", "source": data.get("source", "unknown"),
                "box_name": data.get("box_name", "unknown"), "type": "out_of_scope",
                "created": datetime.now().isoformat(),
            }
        })

    return examples


CONVERTERS = {
    1: convert_layer1,
    2: convert_layer2,
    3: convert_layer3,
    4: convert_layer4,
    5: convert_layer5,
    6: convert_layer6,
    7: convert_layer7,
}


# ── Extraction Logic ───────────────────────────────────────────────────────

def extract_from_writeup(writeup_text: str, layer: int) -> dict | None:
    """Send writeup text to Claude, get structured dict back."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not set")
        return None

    client = Anthropic(api_key=api_key)
    prompt = EXTRACTION_PROMPTS[layer]

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        messages=[{
            "role": "user",
            "content": f"{prompt}\n\n--- WRITEUP TEXT ---\n\n{writeup_text}"
        }]
    )

    raw = response.content[0].text.strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start != -1 and end > start:
            try:
                return json.loads(raw[start:end])
            except json.JSONDecodeError:
                pass
        print(f"ERROR: Could not parse response as JSON")
        print(f"Raw response:\n{raw[:500]}")
        return None


def review_and_confirm(data: dict, layer: int) -> str:
    """Show extracted data to user for review."""
    print(f"\n{'=' * 60}")
    print(f"  Box: {data.get('box_name', 'unknown')}")
    print(f"  Source: {data.get('source', 'unknown')}")
    print(f"  Layer: {layer} — {LAYER_NAMES[layer]}")

    if layer == 1:
        print(f"  Ports: {len(data.get('ports', []))}")
        for p in data.get("ports", []):
            print(f"    - {p.get('port', '?')}/{p.get('proto', '?')} {p.get('service', '?')} {p.get('version', '?')}")
        print(f"  Priorities: {len(data.get('priorities', []))}")
        print(f"  First action: {data.get('first_action', '?')}")
        print(f"  Pivot: {'yes' if data.get('pivot_point') else 'no'}")
        print(f"  Failed attempt: {'yes' if data.get('failed_attempt') else 'no'}")

    elif layer == 2:
        outputs = data.get("tool_outputs", [])
        print(f"  Tool outputs found: {len(outputs)}")
        for t in outputs:
            findings_count = len(t.get("findings", []))
            print(f"    - {t.get('tool', '?')}: {findings_count} findings")

    elif layer == 3:
        failures = data.get("failures", [])
        print(f"  Failures found: {len(failures)}")
        for f in failures:
            print(f"    - {f.get('action', '?')[:60]}...")

    elif layer == 4:
        vulns = data.get("vulnerabilities_found", [])
        print(f"  Vulnerabilities ranked: {len(vulns)}")
        for v in vulns:
            print(f"    - {v.get('vulnerability', '?')[:60]}")
        print(f"  Chosen path: {data.get('chosen_path', '?')}")

    elif layer == 5:
        print(f"  Initial access: {data.get('initial_access', {}).get('user', '?')}")
        print(f"  Enum steps: {len(data.get('enumeration_steps', []))}")
        print(f"  Privesc vector: {data.get('privesc_vector', {}).get('type', '?')}")

    elif layer == 6:
        findings = data.get("findings", [])
        print(f"  Report findings: {len(findings)}")
        for f in findings:
            print(f"    - [{f.get('severity', '?')}] {f.get('title', '?')[:50]}")

    elif layer == 7:
        print(f"  Scope decisions: {len(data.get('scope_decisions', []))}")
        print(f"  OOS discoveries: {len(data.get('out_of_scope_discoveries', []))}")

    print(f"{'=' * 60}")

    while True:
        choice = input("\n[a]pprove / [e]dit manually / [s]kip → ").strip().lower()
        if choice in ("a", "e", "s"):
            return choice
        print("Enter a, e, or s")


def save_examples(examples: list[dict], box_name: str, layer: int):
    """Save examples to processed/{layer_dir}/"""
    layer_dir = LAYER_OUTPUT_DIRS[layer]
    output_dir = PROCESSED_DIR / layer_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    safe_name = re.sub(r"[^a-z0-9]", "_", box_name.lower()).strip("_")
    filename = f"{safe_name}.jsonl"
    filepath = output_dir / filename

    with open(filepath, "a") as f:
        for ex in examples:
            f.write(json.dumps(ex) + "\n")

    print(f"✓ {len(examples)} examples saved → {filepath}")

    tracker_path = METADATA_DIR / f"{layer_dir}_tracker.jsonl"
    with open(tracker_path, "a") as f:
        f.write(json.dumps({
            "box_name": box_name,
            "layer": layer,
            "examples_count": len(examples),
            "source": examples[0]["metadata"]["source"] if examples else "unknown",
            "created": datetime.now().isoformat(),
        }) + "\n")


def process_file(filepath: str, layer: int):
    """Process a single writeup file."""
    path = Path(filepath)
    if not path.exists():
        print(f"File not found: {filepath}")
        return

    writeup_text = path.read_text()
    word_count = len(writeup_text.split())
    print(f"\nLoaded: {path.name} ({word_count} words)")

    if word_count < 50:
        print("WARNING: Very short. May not extract well.")

    print(f"Extracting Layer {layer} ({LAYER_NAMES[layer]}) data...")
    data = extract_from_writeup(writeup_text, layer)

    if not data:
        print("Extraction failed.")
        return

    choice = review_and_confirm(data, layer)

    if choice == "s":
        print("Skipped.")
        return

    if choice == "e":
        edit_path = RAW_DIR / f"{data.get('box_name', 'unknown').lower()}_layer{layer}_extracted.json"
        with open(edit_path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"Saved for editing → {edit_path}")
        return

    converter = CONVERTERS[layer]
    examples = converter(data)

    if not examples:
        print("No examples generated — extraction may be incomplete.")
        return

    save_examples(examples, data.get("box_name", "unknown"), layer)
    print(f"✓ {len(examples)} training examples generated.")


def process_directory(dirpath: str, layer: int):
    """Process all .txt/.md files in a directory."""
    path = Path(dirpath)
    files = sorted(path.glob("*.txt")) + sorted(path.glob("*.md"))

    if not files:
        print(f"No .txt or .md files found in {dirpath}")
        return

    print(f"Found {len(files)} files\n")

    for f in files:
        print(f"\n{'─' * 40}")
        process_file(str(f), layer)


def main():
    parser = argparse.ArgumentParser(
        description="ClawStrike Writeup Extractor v2 — layer-aware",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/writeup_extractor.py raw/vulnhub/layer1/ --layer 1
  python scripts/writeup_extractor.py raw/htb/layer2/ --layer 2
  python scripts/writeup_extractor.py raw/vulnhub/layer3/dc6.txt --layer 3

Output:
  processed/layer1_recon/     (Layer 1)
  processed/layer2_parsing/   (Layer 2)
  processed/layer3_failures/  (Layer 3)
  processed/layer4_exploits/  (Layer 4)
  processed/layer5_postexploit/ (Layer 5)
  processed/layer6_reporting/ (Layer 6)
  processed/layer7_ethics/    (Layer 7)
""",
    )

    parser.add_argument("path", help="File or directory to process")
    parser.add_argument("--layer", type=int, default=1, choices=range(1, 8),
                        help="Which layer to extract (1-7, default: 1)")

    args = parser.parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: Set ANTHROPIC_API_KEY first")
        print("  export ANTHROPIC_API_KEY=your_key_here")
        sys.exit(1)

    target = Path(args.path)
    if target.is_dir():
        process_directory(str(target), args.layer)
    else:
        process_file(str(target), args.layer)


if __name__ == "__main__":
    main()
