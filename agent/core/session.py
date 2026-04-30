from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


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
