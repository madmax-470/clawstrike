from dataclasses import dataclass, field
from typing import Literal


@dataclass
class Action:
    type: Literal["auto_run", "suggest"]
    tool: str
    target: str
    reason: str
    flags: str = ""


# ports that trigger automatic tool execution
# each value is a list of (tool, reason, flags) tuples
AUTO_RUN_PORTS = {
    "80": [
        ("gobuster_scan", "HTTP detected — running directory brute-force", ""),
        ("nikto_scan",    "HTTP detected — running web vulnerability scan", ""),
        ("zap_scan",      "HTTP detected — running ZAP active scan", ""),
    ],
    "443": [
        ("gobuster_scan", "HTTPS detected — running directory brute-force", ""),
        ("nikto_scan",    "HTTPS detected — running web vulnerability scan", "-p 443 -ssl"),
        ("zap_scan",      "HTTPS detected — running ZAP active scan", ""),
    ],
    "8080": [
        ("gobuster_scan", "HTTP alt-port detected — running directory brute-force", ""),
    ],
    "8443": [
        ("gobuster_scan", "HTTPS alt-port detected — running directory brute-force", ""),
    ],
}

# ports that trigger suggestions only
SUGGEST_PORTS = {
    "22":   ("ssh-audit",          "SSH open — run ssh-audit to check ciphers, MACs, and key exchange algorithms"),
    "80":   ("sqlmap_scan",        "HTTP open — if login forms or query params found, run sqlmap_scan <target> to test for SQL injection"),
    "443":  ("sqlmap_scan",        "HTTPS open — if login forms or query params found, run sqlmap_scan <target> to test for SQL injection"),
    "8080": ("sqlmap_scan",        "HTTP alt-port open — if login forms or query params found, run sqlmap_scan <target> to test for SQL injection"),
    "3306": ("mysql enumeration",  "MySQL open — enumerate with: nmap -sV --script=mysql-info,mysql-enum <target>"),
    "5432": ("psql enumeration",   "PostgreSQL open — enumerate with: nmap --script=pgsql-brute <target>"),
    "6379": ("redis-cli",          "Redis open — check for unauthenticated access: redis-cli -h <target> ping"),
    "27017":("mongosh",            "MongoDB open — check for unauthenticated access: mongosh <target>"),
    "21":   ("ftp enumeration",    "FTP open — check anonymous login: nmap --script=ftp-anon <target>"),
    "25":   ("smtp enumeration",   "SMTP open — enumerate users: nmap --script=smtp-enum-users <target>"),
}


def decide_next_tools(scan_result) -> list[Action]:
    """
    Given an nmap ScanResult, return a list of Actions to auto-run or suggest.
    Deduplicates: gobuster only runs once per host even if both 80 and 443 are open.
    """
    actions = []

    if not scan_result or not scan_result.hosts:
        return actions

    for host in scan_result.hosts:
        if not host.ports:
            continue

        target = host.ip
        queued = set()

        for port_info in host.ports:
            port = port_info["port"]

            if port in AUTO_RUN_PORTS:
                for entry in AUTO_RUN_PORTS[port]:
                    tool, reason, flags = entry
                    if tool not in queued:
                        actions.append(Action(
                            type="auto_run",
                            tool=tool,
                            target=target,
                            reason=reason,
                            flags=flags,
                        ))
                        queued.add(tool)

            if port in SUGGEST_PORTS:
                tool, reason = SUGGEST_PORTS[port]
                actions.append(Action(
                    type="suggest",
                    tool=tool,
                    target=target,
                    reason=reason,
                ))

    return actions
