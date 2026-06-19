"""Native function-calling schemas for ClawStrike tools.

These are the structured tool definitions handed to ``router.smart.call_with_tools_text()``
for providers that support native function calling (Anthropic, OpenAI, and
OpenAI-compatible backends). They mirror, one-for-one, the text ``TOOL_CALL:``
protocol described in :data:`agent.core.prompts.SYSTEM_PROMPT`, which remains
the fallback for models without native tool support.

Schemas use the Anthropic tool format::

    {"name": ..., "description": ..., "input_schema": {json-schema}}

The OpenAI conversion (name/description/parameters) happens inside
``agent.core.model_router``.

Argument names here are the canonical keys consumed by
``agent.core.tool_dispatcher.dispatch_tool``.
"""

from __future__ import annotations

TOOL_SCHEMAS: list[dict] = [
    {
        "name": "nmap_scan",
        "description": (
            "Scan, recon, or enumerate a target host with nmap. Use whenever the "
            "user asks to scan a host or discover open ports and services."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP, CIDR, or hostname (e.g. 192.168.1.1).",
                },
                "flags": {
                    "type": "string",
                    "description": "nmap flags. Defaults to -sV (service/version detection).",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "gobuster_scan",
        "description": (
            "Brute-force directories and files on a web server. Suggest this when "
            "port 80 or 443 is open."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Web target, e.g. 192.168.1.1 or 10.0.0.5:8080.",
                },
                "flags": {
                    "type": "string",
                    "description": "Optional extra gobuster flags.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "sqlmap_scan",
        "description": (
            "Test a URL for SQL injection vulnerabilities. Only use when a web port "
            "is open AND there are login forms or query parameters. Always confirm "
            "with the user first — never run automatically."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Full URL with parameters, e.g. http://10.0.0.5/login.php?id=1.",
                },
                "flags": {
                    "type": "string",
                    "description": "Optional extra sqlmap flags.",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "nikto_scan",
        "description": (
            "Scan a web server for known vulnerabilities, misconfigurations, and "
            "exposed files. Triggered automatically when port 80/443 is open."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Web target host or IP.",
                },
                "flags": {
                    "type": "string",
                    "description": "Optional nikto flags, e.g. -p 443 -ssl.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "zap_scan",
        "description": (
            "Run an OWASP ZAP active scan (spider + active scan + alert collection) "
            "against a web target."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Web target URL, e.g. http://10.0.0.5:8080.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "hydra_scan",
        "description": (
            "Credential brute-force against a network service. Use ONLY when the "
            "user explicitly asks to brute-force credentials. Never suggest or run "
            "automatically. The user is prompted to confirm before execution."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname."},
                "service": {
                    "type": "string",
                    "description": "Service to attack, e.g. ssh, ftp, http-post-form.",
                },
                "flags": {
                    "type": "string",
                    "description": "Hydra flags, e.g. -l admin -P /usr/share/wordlists/rockyou.txt.",
                },
            },
            "required": ["target", "service"],
        },
    },
    {
        "name": "mitm_capture",
        "description": (
            "Intercept and inspect live HTTP traffic to/from a target to find hidden "
            "endpoints, auth tokens, cookies, or API calls. Only use when the user "
            "asks to intercept traffic. Never run automatically."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL, e.g. http://192.168.1.1.",
                },
                "port": {
                    "type": "integer",
                    "description": "Proxy port to listen on. Defaults to 8080.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "msf_search",
        "description": (
            "Search Metasploit for exploit modules matching a service, version, or "
            "CVE. Run when nmap finds a service version that may have known exploits. "
            "Never run exploits automatically — present options first."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Service name, CVE id, or module keyword (e.g. ssh, CVE-2017-0144, ms17_010).",
                },
                "version": {
                    "type": "string",
                    "description": "Optional service version to narrow results.",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "msf_exploit",
        "description": (
            "Execute a Metasploit exploit module against a target. NEVER run "
            "automatically and NEVER without explicit user request. The user is shown "
            "exactly what will run and must confirm."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "module": {
                    "type": "string",
                    "description": "Exploit module path, e.g. exploit/windows/smb/ms17_010_eternalblue.",
                },
                "target": {"type": "string", "description": "Target IP or hostname (RHOSTS)."},
                "lhost": {"type": "string", "description": "Local host for the reverse connection (LHOST)."},
                "lport": {"type": "string", "description": "Optional local port (LPORT)."},
                "payload": {"type": "string", "description": "Optional payload override."},
            },
            "required": ["module", "target", "lhost"],
        },
    },
    {
        "name": "msf_sessions",
        "description": (
            "List all active Metasploit meterpreter and shell sessions. Run after an "
            "exploit to check whether a session was opened."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "msf_post",
        "description": (
            "Run a post-exploitation module on an active session. Only on explicit "
            "user request — never automatically."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active session id from msf_sessions.",
                },
                "module": {
                    "type": "string",
                    "description": "Post module path, e.g. post/multi/recon/local_exploit_suggester.",
                },
            },
            "required": ["session_id", "module"],
        },
    },
]


# Quick lookup by tool name, handy for validation/debugging.
TOOL_SCHEMA_BY_NAME: dict[str, dict] = {t["name"]: t for t in TOOL_SCHEMAS}
