"""
ClawStrike — Writeup Extractor (v3)
=====================================
Takes raw writeup text files and uses Claude API to extract structured
training data. Supports manual review or auto-approve mode.

Now layer-aware — saves to processed/{layer_name}/ automatically.

Usage:
  python scripts/writeup_extractor.py <path> [--layer N] [--auto]

Examples:
  # Manual review (one by one)
  python scripts/writeup_extractor.py raw/vulnhub/layer1/ --layer 1

  # Auto mode — approve all, get summary report
  python scripts/writeup_extractor.py raw/vulnhub/layer2/ --layer 2 --auto

  # Single file
  python scripts/writeup_extractor.py raw/htb/layer3/lame.txt --layer 3
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

    ports = data.get("ports") or []
    priorities = data.get("priorities") or []

    ports_text = "\n".join(
        f"- {p['port']}/{p['proto']} {p['service']} {p.get('version', 'unknown')}"
        for p in ports
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
    for i, p in enumerate(priorities, 1):
        reasoning_lines.append(f"{i}. {p.get('service', '?')} — {p.get('reasoning', '?')}")

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

    for tool_entry in (data.get("tool_outputs") or []):
        instruction = (
            f"You are a penetration tester conducting authorized testing.\n"
            f"Parse the following {tool_entry.get('tool', 'unknown')} output and extract key findings.\n\n"
            f"Command: {tool_entry.get('command', 'unknown')}\n\n"
            f"Raw output:\n{tool_entry.get('raw_output', '')}"
        )

        findings_text = []
        for i, f in enumerate(tool_entry.get("findings") or [], 1):
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

    for failure in (data.get("failures") or []):
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

    vulns = data.get("vulnerabilities_found") or []
    if not vulns:
        return examples

    vuln_text = "\n".join(
        f"- {v.get('service', '?')}: {v.get('vulnerability', '?')}" for v in vulns
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

    initial = data.get("initial_access") or {}
    steps = data.get("enumeration_steps") or []
    privesc = data.get("privesc_vector") or {}

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

    failed = data.get("failed_privesc") or []
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

    for finding in (data.get("findings") or []):
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

    for decision in (data.get("scope_decisions") or []):
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

    for discovery in (data.get("out_of_scope_discoveries") or []):
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


def load_processed_files(layer: int) -> set:
    """Load set of already-processed filenames for this layer."""
    tracker = METADATA_DIR / f"processed_files_layer{layer}.txt"
    if tracker.exists():
        return set(line.strip() for line in tracker.read_text().splitlines() if line.strip())
    return set()


def rebuild_tracker_from_existing(layer: int) -> set:
    """Scan existing processed JSONL files and rebuild the tracker.
    Called once on first run to catch files processed before tracking existed."""
    tracker = METADATA_DIR / f"processed_files_layer{layer}.txt"

    # If tracker already exists, don't rebuild
    if tracker.exists():
        return load_processed_files(layer)

    # Check the layer tracker JSONL in metadata for previously processed boxes
    layer_dir = LAYER_OUTPUT_DIRS[layer]
    layer_tracker = METADATA_DIR / f"{layer_dir}_tracker.jsonl"
    existing = set()

    if layer_tracker.exists():
        try:
            with open(layer_tracker) as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        box = entry.get("box_name", "")
                        if box:
                            safe = re.sub(r"[^a-z0-9]", "_", box.lower()).strip("_")
                            existing.add(f"{safe}.txt")
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass

    # Also check which JSONL files already exist in processed/
    output_dir = PROCESSED_DIR / layer_dir
    if output_dir.exists():
        for jsonl_file in output_dir.glob("*.jsonl"):
            # If lame.jsonl exists, then lame.txt was processed
            existing.add(jsonl_file.stem + ".txt")

    if existing:
        with open(tracker, "w") as f:
            f.write("\n".join(sorted(existing)) + "\n")
        print(f"  [info] Found {len(existing)} previously processed files")

    return existing


def mark_processed(filename: str, layer: int):
    """Mark a file as processed for this layer."""
    tracker = METADATA_DIR / f"processed_files_layer{layer}.txt"
    with open(tracker, "a") as f:
        f.write(filename + "\n")


def process_file(filepath: str, layer: int, auto: bool = False, processed_set: set = None) -> dict:
    """Process a single writeup file. Returns result dict for reporting."""
    result = {"file": Path(filepath).name, "status": "unknown", "examples": 0, "box": "unknown"}

    path = Path(filepath)
    if not path.exists():
        print(f"File not found: {filepath}")
        result["status"] = "file_not_found"
        return result

    # Dedup check
    if processed_set is not None and path.name in processed_set:
        if auto:
            print(f"  {path.name}... SKIP (already processed)")
        else:
            print(f"\nSkipping {path.name} — already processed for Layer {layer}")
        result["status"] = "duplicate"
        return result

    writeup_text = path.read_text()
    word_count = len(writeup_text.split())

    if auto:
        print(f"  {path.name} ({word_count} words)...", end=" ", flush=True)
    else:
        print(f"\nLoaded: {path.name} ({word_count} words)")

    if word_count < 50:
        if auto:
            print("SKIP (too short)")
            result["status"] = "too_short"
            return result
        else:
            print("WARNING: Very short. May not extract well.")

    if not auto:
        print(f"Extracting Layer {layer} ({LAYER_NAMES[layer]}) data...")

    try:
        data = extract_from_writeup(writeup_text, layer)
    except Exception as e:
        if auto:
            print(f"FAIL (API error: {e})")
        else:
            print(f"API error: {e}")
        result["status"] = "api_error"
        return result

    if not data:
        if auto:
            print("FAIL (extraction error)")
        else:
            print("Extraction failed.")
        result["status"] = "extraction_failed"
        return result

    result["box"] = data.get("box_name", "unknown")

    # In auto mode, skip review and approve everything
    if not auto:
        choice = review_and_confirm(data, layer)

        if choice == "s":
            print("Skipped.")
            result["status"] = "skipped"
            return result

        if choice == "e":
            edit_path = RAW_DIR / f"{data.get('box_name', 'unknown').lower()}_layer{layer}_extracted.json"
            with open(edit_path, "w") as f:
                json.dump(data, f, indent=2)
            print(f"Saved for editing → {edit_path}")
            result["status"] = "saved_for_edit"
            return result

    converter = CONVERTERS[layer]
    try:
        examples = converter(data)
    except Exception as e:
        if auto:
            print(f"FAIL (converter error: {e})")
        else:
            print(f"Converter error: {e}")
        result["status"] = "converter_error"
        return result

    if not examples:
        if auto:
            print("SKIP (no examples generated)")
        else:
            print("No examples generated — extraction may be incomplete.")
        result["status"] = "no_examples"
        return result

    save_examples(examples, data.get("box_name", "unknown"), layer)
    mark_processed(Path(filepath).name, layer)
    result["status"] = "success"
    result["examples"] = len(examples)

    if auto:
        print(f"✓ {len(examples)} examples")
    else:
        print(f"✓ {len(examples)} training examples generated.")

    return result


def process_directory(dirpath: str, layer: int, auto: bool = False):
    """Process all .txt/.md files in a directory."""
    path = Path(dirpath)
    files = sorted(path.glob("*.txt")) + sorted(path.glob("*.md"))

    if not files:
        print(f"No .txt or .md files found in {dirpath}")
        return

    # Load already-processed files (auto-rebuilds tracker on first run)
    processed_set = rebuild_tracker_from_existing(layer)
    new_files = [f for f in files if f.name not in processed_set]

    layer_name = LAYER_NAMES[layer]
    print(f"\n{'═' * 60}")
    print(f"  ClawStrike Extractor {'(AUTO MODE)' if auto else ''}")
    print(f"  Layer {layer}: {layer_name}")
    print(f"  Total files found:    {len(files)}")
    print(f"  Already processed:    {len(files) - len(new_files)}")
    print(f"  New files to process: {len(new_files)}")
    print(f"  Mode: {'auto-approve' if auto else 'manual review'}")
    print(f"  Output: processed/{LAYER_OUTPUT_DIRS[layer]}/")
    print(f"{'═' * 60}\n")

    if not new_files:
        print("  Nothing new to process. All files already extracted.")
        return

    results = []
    for i, f in enumerate(new_files, 1):
        if auto:
            print(f"  [{i}/{len(new_files)}]", end=" ")
        else:
            print(f"\n{'─' * 40}")
        result = process_file(str(f), layer, auto, processed_set)
        results.append(result)

    # ── Summary Report ──────────────────────────────────────────
    total = len(results)
    succeeded = [r for r in results if r["status"] == "success"]
    failed_extract = [r for r in results if r["status"] == "extraction_failed"]
    no_examples = [r for r in results if r["status"] == "no_examples"]
    too_short = [r for r in results if r["status"] == "too_short"]
    skipped = [r for r in results if r["status"] == "skipped"]
    duplicates = [r for r in results if r["status"] == "duplicate"]
    api_errors = [r for r in results if r["status"] == "api_error"]
    converter_errors = [r for r in results if r["status"] == "converter_error"]
    total_examples = sum(r["examples"] for r in results)

    print(f"\n{'═' * 60}")
    print(f"  EXTRACTION REPORT — Layer {layer}: {layer_name}")
    print(f"{'═' * 60}")
    print(f"  Files in directory:       {len(files)}")
    print(f"  Previously processed:     {len(files) - len(new_files)}")
    print(f"  New files processed:      {total}")
    print(f"  {'─' * 40}")
    print(f"  ✅ Successful:             {len(succeeded)}")
    if failed_extract:
        print(f"  ❌ Extraction failed:      {len(failed_extract)}")
    if api_errors:
        print(f"  ❌ API errors:             {len(api_errors)}")
    if converter_errors:
        print(f"  ❌ Converter errors:       {len(converter_errors)}")
    if no_examples:
        print(f"  ⚠️  No examples generated:  {len(no_examples)}")
    if too_short:
        print(f"  ⏭️  Too short (skipped):    {len(too_short)}")
    if skipped:
        print(f"  ⏭️  Manually skipped:       {len(skipped)}")
    if duplicates:
        print(f"  🔄 Duplicates skipped:     {len(duplicates)}")
    print(f"  {'─' * 40}")
    print(f"  📊 New training examples:  {total_examples}")
    print(f"  📁 Saved to: processed/{LAYER_OUTPUT_DIRS[layer]}/")

    if failed_extract or api_errors or converter_errors:
        print(f"\n  Failed files:")
        for r in failed_extract + api_errors + converter_errors:
            print(f"    ✗ {r['file']} ({r['status']})")

    if no_examples:
        print(f"\n  No examples generated:")
        for r in no_examples:
            print(f"    ⚠ {r['file']} ({r['box']})")

    # Save report to metadata
    report_path = METADATA_DIR / f"extraction_report_layer{layer}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report = {
        "layer": layer,
        "layer_name": layer_name,
        "timestamp": datetime.now().isoformat(),
        "total_in_directory": len(files),
        "previously_processed": len(files) - len(new_files),
        "new_processed": total,
        "successful": len(succeeded),
        "failed": len(failed_extract),
        "api_errors": len(api_errors),
        "converter_errors": len(converter_errors),
        "no_examples": len(no_examples),
        "too_short": len(too_short),
        "skipped": len(skipped),
        "duplicates": len(duplicates),
        "total_examples": total_examples,
        "results": results,
    }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n  📋 Report saved: {report_path}")
    print(f"{'═' * 60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="ClawStrike Writeup Extractor v2 — layer-aware",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Manual review mode (one by one)
  python scripts/writeup_extractor.py raw/vulnhub/layer1/ --layer 1

  # Auto mode — approve all, get report at end
  python scripts/writeup_extractor.py raw/vulnhub/layer2/ --layer 2 --auto

  # Single file
  python scripts/writeup_extractor.py raw/htb/layer3/lame.txt --layer 3

  # Reprocess everything (clear dedup tracker first)
  python scripts/writeup_extractor.py raw/vulnhub/layer1/ --layer 1 --auto --reset

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
    parser.add_argument("--auto", action="store_true",
                        help="Auto-approve all extractions, print summary report at end")
    parser.add_argument("--reset", action="store_true",
                        help="Clear dedup tracker and reprocess everything from scratch")

    args = parser.parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: Set ANTHROPIC_API_KEY first")
        print("  export ANTHROPIC_API_KEY=your_key_here")
        sys.exit(1)

    # Reset tracker if requested
    if args.reset:
        tracker = METADATA_DIR / f"processed_files_layer{args.layer}.txt"
        if tracker.exists():
            tracker.unlink()
            print(f"  [reset] Cleared tracker for Layer {args.layer}")

    target = Path(args.path)
    if target.is_dir():
        process_directory(str(target), args.layer, args.auto)
    else:
        processed_set = rebuild_tracker_from_existing(args.layer)
        process_file(str(target), args.layer, args.auto, processed_set)


if __name__ == "__main__":
    main()
