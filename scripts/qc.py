"""
ClawStrike — Raw File Quality Checker
=======================================
Validates raw writeup files against training data standards.
Gives a PASS/FAIL verdict with specific issues flagged.

Usage:
  python scripts/quality_check.py <file_or_directory> [--layer N] [--strict]

Examples:
  python scripts/quality_check.py raw/htb/blue.txt --layer 1
  python scripts/quality_check.py raw/htb/ --layer 1
  python scripts/quality_check.py raw/htb/ --layer 1 --strict
"""

import argparse
import re
import sys
from pathlib import Path

# ── Quality Rules Per Layer ─────────────────────────────────────────────────

LAYER_CHECKS = {
    1: {
        "name": "Recon Decision Trees",
        "required": [
            {
                "name": "Raw scan output present",
                "patterns": [
                    r"\d+/tcp\s+(open|closed|filtered)",
                    r"nmap",
                    r"PORT\s+STATE\s+SERVICE",
                ],
                "match_any": True,
                "reason": "Layer 1 needs real scan output with port/service data",
            },
            {
                "name": "Service versions included",
                "patterns": [
                    r"\d+\.\d+",
                    r"version",
                    r"OpenSSH|Apache|nginx|vsftpd|Samba|IIS|MySQL|PostgreSQL|ProFTPD|Tomcat|Redis|MongoDB",
                ],
                "match_any": True,
                "reason": "Version numbers are critical for exploit probability reasoning",
            },
            {
                "name": "Decision reasoning present",
                "patterns": [
                    r"(tried|attempt|decided|chose|priorit|first|next|because|since|likely|vulnerab|exploit)",
                ],
                "match_any": True,
                "reason": "Must show WHY decisions were made, not just WHAT was done",
            },
        ],
        "forbidden": [
            {
                "name": "No pure summary format",
                "patterns": [
                    r"CRITICAL VECTORS:",
                    r"EXPLOITATION PATH IDENTIFIED",
                    r"KEY FINDINGS:\s*\n-+\s*\n\d+\.",
                ],
                "match_any": True,
                "reason": "Study-guide summaries don't capture decision-making process",
            },
        ],
        "min_words": 200,
        "max_words": 8000,
        "should_have": [
            {
                "name": "Multiple ports/services",
                "patterns": [r"\d+/tcp"],
                "min_matches": 2,
                "reason": "Multiple services needed to show prioritization logic",
            },
            {
                "name": "Commands shown",
                "patterns": [
                    r"(nmap|gobuster|nikto|smbclient|smbmap|searchsploit|curl|wget|dirb|ffuf|enum4linux)\s",
                ],
                "match_any": True,
                "reason": "Real commands help show the enumeration workflow",
            },
            {
                "name": "Fallback or alternative path mentioned",
                "patterns": [
                    r"(fallback|alternative|instead|pivot|also tried|didn.t work|failed|another)",
                ],
                "match_any": True,
                "reason": "Good training data shows alternatives and fallback reasoning",
            },
        ],
    },
    2: {
        "name": "Tool Output Parsing",
        "required": [
            {
                "name": "Raw tool output present",
                "patterns": [
                    r"(PORT\s+STATE|Starting Nmap|\[\+\]|\[\-\]|\[\*\]|HTTP/\d|200 OK|403 Forbidden|301 Moved)",
                ],
                "match_any": True,
                "reason": "Layer 2 needs real, unparsed tool output",
            },
            {
                "name": "Tool identification",
                "patterns": [
                    r"(nmap|gobuster|nikto|sqlmap|hydra|enum4linux|smbclient|searchsploit|zap|burp|dirb|ffuf)",
                ],
                "match_any": True,
                "reason": "Must identify which tool produced the output",
            },
        ],
        "forbidden": [],
        "min_words": 150,
        "max_words": 10000,
        "should_have": [
            {
                "name": "Analysis of output",
                "patterns": [
                    r"(found|discovered|interesting|notable|important|vulnerable|misconfigur|exposed)",
                ],
                "match_any": True,
                "reason": "Need interpretation of what the output means",
            },
        ],
    },
    3: {
        "name": "Failed Paths + Pivots",
        "required": [
            {
                "name": "Failure described",
                "patterns": [
                    r"(fail|didn.t work|error|denied|refused|timeout|no.*(found|result|access)|unsuccessful|dead end|rabbit hole)",
                ],
                "match_any": True,
                "reason": "Layer 3 must describe what went wrong",
            },
            {
                "name": "Recovery or pivot action",
                "patterns": [
                    r"(instead|pivot|switch|try|next|alternative|moved to|fell back|changed|different approach)",
                ],
                "match_any": True,
                "reason": "Must show how the tester recovered from failure",
            },
        ],
        "forbidden": [],
        "min_words": 100,
        "max_words": 6000,
        "should_have": [
            {
                "name": "Reasoning about WHY it failed",
                "patterns": [
                    r"(because|reason|likely|probably|patch|filter|block|sanitiz|protect|configured)",
                ],
                "match_any": True,
                "reason": "Understanding failure cause is the key learning",
            },
        ],
    },
    4: {
        "name": "Exploit Ranking",
        "required": [
            {
                "name": "Multiple vulnerabilities listed",
                "patterns": [
                    r"(CVE-\d{4}|MS\d{2}-\d{3}|vulnerab|exploit|RCE|LFI|SQLi|XSS|SSRF|upload)",
                ],
                "match_any": True,
                "reason": "Layer 4 needs multiple vulnerabilities to rank",
            },
            {
                "name": "Prioritization reasoning",
                "patterns": [
                    r"(priority|first|rank|probabilit|impact|reliable|critical|high|medium|low|risk)",
                ],
                "match_any": True,
                "reason": "Must show ranking logic, not just list vulnerabilities",
            },
        ],
        "forbidden": [],
        "min_words": 150,
        "max_words": 6000,
        "should_have": [
            {
                "name": "Impact assessment",
                "patterns": [
                    r"(SYSTEM|root|admin|RCE|remote code|full access|credential|privilege)",
                ],
                "match_any": True,
                "reason": "Should assess what each exploit gives you",
            },
        ],
    },
    5: {
        "name": "Post-Exploitation Reasoning",
        "required": [
            {
                "name": "Shell access context",
                "patterns": [
                    r"(shell|whoami|id |www-data|user|low.priv|foothold|initial access|meterpreter|\$\s)",
                ],
                "match_any": True,
                "reason": "Layer 5 starts from having a shell — must establish context",
            },
            {
                "name": "Privilege escalation content",
                "patterns": [
                    r"(privesc|privilege|escalat|root|SYSTEM|sudo|SUID|cron|kernel|linpeas|winpeas|exploit suggest)",
                ],
                "match_any": True,
                "reason": "Must cover how to escalate from initial access",
            },
        ],
        "forbidden": [],
        "min_words": 150,
        "max_words": 8000,
        "should_have": [
            {
                "name": "System enumeration shown",
                "patterns": [
                    r"(uname|systeminfo|whoami|id |cat /etc|ipconfig|ifconfig|netstat|ps aux|tasklist)",
                ],
                "match_any": True,
                "reason": "Should show system enumeration commands and output",
            },
        ],
    },
    6: {
        "name": "Reporting Intelligence",
        "required": [
            {
                "name": "Vulnerability finding present",
                "patterns": [
                    r"(vulnerab|finding|issue|weakness|misconfigur|exposure|flaw)",
                ],
                "match_any": True,
                "reason": "Layer 6 needs clear vulnerability findings",
            },
            {
                "name": "Evidence present",
                "patterns": [
                    r"(evidence|proof|confirmed|verified|demonstrated|output|screenshot|log)",
                ],
                "match_any": True,
                "reason": "Findings must have evidence to back them up",
            },
        ],
        "forbidden": [],
        "min_words": 100,
        "max_words": 6000,
        "should_have": [
            {
                "name": "Severity mentioned",
                "patterns": [
                    r"(critical|high|medium|low|info|CVSS|severity|impact|risk)",
                ],
                "match_any": True,
                "reason": "Report findings need severity ratings",
            },
            {
                "name": "Remediation mentioned",
                "patterns": [
                    r"(remediat|fix|patch|mitigat|recommend|upgrad|disabl|configur|harden)",
                ],
                "match_any": True,
                "reason": "Good report findings include remediation steps",
            },
        ],
    },
    7: {
        "name": "Ethics + Scope Enforcement",
        "required": [
            {
                "name": "Scope or authorization context",
                "patterns": [
                    r"(scope|authoriz|permission|allowed|legal|boundary|engagement|rules of engagement|out.of.scope|unauthorized)",
                ],
                "match_any": True,
                "reason": "Layer 7 must involve scope or authorization decisions",
            },
        ],
        "forbidden": [],
        "min_words": 50,
        "max_words": 4000,
        "should_have": [
            {
                "name": "Decision reasoning",
                "patterns": [
                    r"(should not|must not|cannot|refuse|stop|document|report|recommend|instead)",
                ],
                "match_any": True,
                "reason": "Should show reasoning about ethical decisions",
            },
        ],
    },
}


# ── Check Functions ─────────────────────────────────────────────────────────

def count_pattern_matches(text: str, pattern: str) -> int:
    return len(re.findall(pattern, text, re.IGNORECASE))


def check_patterns(text: str, check: dict) -> bool:
    if check.get("match_any"):
        return any(
            re.search(p, text, re.IGNORECASE) for p in check["patterns"]
        )
    if check.get("min_matches"):
        total = sum(
            count_pattern_matches(text, p) for p in check["patterns"]
        )
        return total >= check["min_matches"]
    return all(
        re.search(p, text, re.IGNORECASE) for p in check["patterns"]
    )


def check_file(filepath: Path, layer: int, strict: bool = False) -> dict:
    """Run all quality checks on a single file. Returns result dict."""

    config = LAYER_CHECKS[layer]
    text = filepath.read_text(errors="replace")
    word_count = len(text.split())

    result = {
        "file": filepath.name,
        "layer": layer,
        "layer_name": config["name"],
        "word_count": word_count,
        "passed": [],
        "failed": [],
        "warnings": [],
        "verdict": "PASS",
    }

    # Word count check
    if word_count < config["min_words"]:
        result["failed"].append(
            f"Too short: {word_count} words (minimum {config['min_words']})"
        )
    elif word_count > config["max_words"]:
        result["warnings"].append(
            f"Very long: {word_count} words (max recommended {config['max_words']})"
        )
    else:
        result["passed"].append(f"Word count OK: {word_count}")

    # Required checks (must pass)
    for check in config["required"]:
        if check_patterns(text, check):
            result["passed"].append(f"✓ {check['name']}")
        else:
            result["failed"].append(f"✗ {check['name']} — {check['reason']}")

    # Forbidden checks (must not match)
    for check in config.get("forbidden", []):
        if check_patterns(text, check):
            if strict:
                result["failed"].append(f"✗ FORBIDDEN: {check['name']} — {check['reason']}")
            else:
                result["warnings"].append(f"⚠ {check['name']} — {check['reason']}")

    # Should-have checks (warnings only, failures in strict mode)
    for check in config.get("should_have", []):
        if check_patterns(text, check):
            result["passed"].append(f"✓ {check['name']}")
        else:
            if strict:
                result["failed"].append(f"✗ {check['name']} — {check['reason']}")
            else:
                result["warnings"].append(f"⚠ {check['name']} — {check['reason']}")

    # Final verdict
    if result["failed"]:
        result["verdict"] = "FAIL"
    elif result["warnings"] and strict:
        result["verdict"] = "WARN"
    elif result["warnings"]:
        result["verdict"] = "PASS (with warnings)"

    return result


# ── Display ─────────────────────────────────────────────────────────────────

def print_result(result: dict):
    """Pretty print a single file's check result."""

    verdict = result["verdict"]
    if "FAIL" in verdict:
        badge = "❌ FAIL"
        color_start = "\033[91m"  # red
    elif "WARN" in verdict or "warning" in verdict:
        badge = "⚠️  PASS (warnings)"
        color_start = "\033[93m"  # yellow
    else:
        badge = "✅ PASS"
        color_start = "\033[92m"  # green

    color_end = "\033[0m"

    print(f"\n{'─' * 60}")
    print(f"  {color_start}{badge}{color_end}  {result['file']}")
    print(f"  Layer {result['layer']}: {result['layer_name']}")
    print(f"  Words: {result['word_count']}")

    if result["passed"]:
        print(f"\n  Passed:")
        for p in result["passed"]:
            print(f"    {p}")

    if result["warnings"]:
        print(f"\n  \033[93mWarnings:\033[0m")
        for w in result["warnings"]:
            print(f"    {w}")

    if result["failed"]:
        print(f"\n  \033[91mFailed:\033[0m")
        for f in result["failed"]:
            print(f"    {f}")


def print_summary(results: list):
    """Print overall summary of all checked files."""

    total = len(results)
    passed = sum(1 for r in results if r["verdict"] == "PASS")
    warned = sum(1 for r in results if "warning" in r["verdict"].lower())
    failed = sum(1 for r in results if "FAIL" in r["verdict"])

    print(f"\n{'═' * 60}")
    print(f"  QUALITY CHECK SUMMARY")
    print(f"{'═' * 60}")
    print(f"  Total files:  {total}")
    print(f"  \033[92mPassed:       {passed}\033[0m")
    if warned:
        print(f"  \033[93mWarnings:     {warned}\033[0m")
    if failed:
        print(f"  \033[91mFailed:       {failed}\033[0m")
    print(f"{'═' * 60}")

    if failed:
        print(f"\n  Failed files need fixing before extraction:")
        for r in results:
            if "FAIL" in r["verdict"]:
                print(f"    ✗ {r['file']}")
                for f in r["failed"]:
                    print(f"      → {f}")

    print()


# ── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ClawStrike Raw File Quality Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/quality_check.py raw/htb/blue.txt --layer 1
  python scripts/quality_check.py raw/htb/ --layer 1
  python scripts/quality_check.py raw/htb/ --layer 1 --strict
  python scripts/quality_check.py raw/failures/ --layer 3
  python scripts/quality_check.py raw/post_exploit/ --layer 5 --strict
""",
    )

    parser.add_argument("path", help="File or directory to check")
    parser.add_argument("--layer", type=int, default=1, choices=range(1, 8),
                        help="Which layer's standards to check against (1-7)")
    parser.add_argument("--strict", action="store_true",
                        help="Treat warnings as failures")

    args = parser.parse_args()
    path = Path(args.path)

    if not path.exists():
        print(f"ERROR: {args.path} not found")
        sys.exit(1)

    print(f"\n{'═' * 60}")
    print(f"  ClawStrike Quality Checker")
    print(f"  Layer {args.layer}: {LAYER_CHECKS[args.layer]['name']}")
    print(f"  Mode: {'STRICT' if args.strict else 'STANDARD'}")
    print(f"{'═' * 60}")

    if path.is_file():
        result = check_file(path, args.layer, args.strict)
        print_result(result)
        print()
    else:
        files = sorted(path.glob("*.txt")) + sorted(path.glob("*.md"))
        if not files:
            print(f"\n  No .txt or .md files found in {args.path}")
            sys.exit(1)

        results = []
        for f in files:
            result = check_file(f, args.layer, args.strict)
            print_result(result)
            results.append(result)

        print_summary(results)


if __name__ == "__main__":
    main()
