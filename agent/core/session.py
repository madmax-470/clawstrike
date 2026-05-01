from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


# ── Base directory resolution ─────────────────────────────────────────────────

def get_base_dir() -> str:
    """
    Find the ClawStrike base directory dynamically.

    Tries in order:
    1. CLAWSTRIKE_HOME environment variable
    2. Parent of the agent/ directory (where this file lives), if writable
    3. ~/clawstrike (home directory fallback)
    4. /opt/clawstrike (system install fallback — last resort)
    """
    # 1. explicit env var override
    if os.environ.get("CLAWSTRIKE_HOME"):
        return os.environ["CLAWSTRIKE_HOME"]

    # 2. derive from this file: agent/core/session.py → go up 2 levels
    this_file = os.path.abspath(__file__)
    derived = os.path.dirname(os.path.dirname(os.path.dirname(this_file)))
    if os.path.exists(derived) and os.access(derived, os.W_OK):
        return derived

    # 3. home directory fallback
    home_path = os.path.expanduser("~/clawstrike")
    if os.path.exists(home_path) and os.access(home_path, os.W_OK):
        return home_path

    # 4. last resort
    return "/opt/clawstrike"


BASE_DIR = get_base_dir()
ENGAGEMENTS_DIR = os.path.join(BASE_DIR, "engagements")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

os.makedirs(ENGAGEMENTS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)


@dataclass
class ExploitOption:
    number: int
    title: str
    cve: str
    cvss: float
    port: int
    service: str
    version: str
    msf_module: str    # empty string if none
    manual_cmd: str    # direct command if no MSF
    confidence: str    # high / medium / low
    notes: str


@dataclass
class EngagementSession:
    target: str
    profile: str
    scope: str
    open_ports: list = field(default_factory=list)
    services: dict = field(default_factory=dict)    # port → {service, version}
    findings: list = field(default_factory=list)
    exploit_options: list = field(default_factory=list)
    shells: list = field(default_factory=list)      # acquired shells
    loot: list = field(default_factory=list)        # harvested data

    def add_exploit(self, option: ExploitOption) -> None:
        option.number = len(self.exploit_options) + 1
        self.exploit_options.append(option)

    def get_exploit(self, number: int) -> Optional[ExploitOption]:
        for opt in self.exploit_options:
            if opt.number == number:
                return opt
        return None
