from dataclasses import dataclass


@dataclass
class ScanProfile:
    name: str
    phase1_cmd: str       # nmap discovery command template ({target} placeholder)
    phase2_cmd: str       # nmap service-id command template ({ports} and {target} placeholders)
    phase3_timeout: int   # seconds per tool in phase 3
    notes: str


PROFILES: dict[str, ScanProfile] = {
    "stealth": ScanProfile(
        name="STEALTH",
        phase1_cmd="nmap -sn --top-ports 20 {target}",
        phase2_cmd="nmap -sV -p {ports} {target}",
        phase3_timeout=60,
        notes="Minimal noise. Reduced port range. IDS evasion.",
    ),
    "standard": ScanProfile(
        name="STANDARD",
        phase1_cmd="nmap --top-ports 100 {target}",
        phase2_cmd="nmap -sV -p {ports} {target}",
        phase3_timeout=120,
        notes="Balanced. Good for most engagements.",
    ),
    "thorough": ScanProfile(
        name="THOROUGH",
        phase1_cmd="nmap --top-ports 1000 {target}",
        phase2_cmd="nmap -sV -sC -p {ports} {target}",
        phase3_timeout=300,
        notes="More complete. Slower. Runs NSE scripts.",
    ),
    "full": ScanProfile(
        name="FULL",
        phase1_cmd="nmap -p- {target}",
        phase2_cmd="nmap -sV -sC -O -p {ports} {target}",
        phase3_timeout=600,
        notes="All 65535 ports. OS detection. Use when time is not a concern.",
    ),
}

DEFAULT_PROFILE = "standard"


def get_profile(name: str) -> ScanProfile:
    return PROFILES.get(name.lower(), PROFILES[DEFAULT_PROFILE])
