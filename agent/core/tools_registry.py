from dataclasses import dataclass


@dataclass
class Tool:
    name: str        # display name
    binary: str      # binary checked by shutil.which()
    apt: str         # apt install command
    pip: str         # pip install spec (empty string if not needed)
    critical: bool   # True = warn loudly on startup if missing
    fallback: bool   # True = stdlib manual fallback available


REGISTRY: dict[str, Tool] = {
    "nmap": Tool(
        name="nmap",
        binary="nmap",
        apt="apt install -y nmap",
        pip="",
        critical=True,
        fallback=True,
    ),
    "gobuster": Tool(
        name="gobuster",
        binary="gobuster",
        apt="apt install -y gobuster",
        pip="",
        critical=False,
        fallback=True,
    ),
    "sqlmap": Tool(
        name="sqlmap",
        binary="sqlmap",
        apt="apt install -y sqlmap",
        pip="",
        critical=False,
        fallback=False,
    ),
    "nikto": Tool(
        name="nikto",
        binary="nikto",
        apt="apt install -y nikto",
        pip="",
        critical=False,
        fallback=True,
    ),
    "hydra": Tool(
        name="hydra",
        binary="hydra",
        apt="apt install -y hydra",
        pip="",
        critical=False,
        fallback=False,
    ),
    "metasploit": Tool(
        name="metasploit",
        binary="msfconsole",
        apt="apt install -y metasploit-framework",
        pip="",
        critical=False,
        fallback=False,
    ),
    "zaproxy": Tool(
        name="zaproxy",
        binary="zaproxy",
        apt="apt install -y zaproxy",
        pip="",
        critical=False,
        fallback=False,
    ),
    "mitmproxy": Tool(
        name="mitmproxy",
        binary="mitmproxy",
        apt="apt install -y mitmproxy",
        pip="mitmproxy>=10.0.0",
        critical=False,
        fallback=False,
    ),
    "ffuf": Tool(
        name="ffuf",
        binary="ffuf",
        apt="apt install -y ffuf",
        pip="",
        critical=False,
        fallback=False,
    ),
    "ssh-audit": Tool(
        name="ssh-audit",
        binary="ssh-audit",
        apt="apt install -y ssh-audit",
        pip="",
        critical=False,
        fallback=False,
    ),
    "enum4linux": Tool(
        name="enum4linux",
        binary="enum4linux",
        apt="apt install -y enum4linux",
        pip="",
        critical=False,
        fallback=False,
    ),
    "netexec": Tool(
        name="netexec",
        binary="netexec",
        apt="apt install -y netexec",
        pip="",
        critical=False,
        fallback=False,
    ),
}
