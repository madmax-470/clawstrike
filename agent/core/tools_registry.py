from dataclasses import dataclass


@dataclass
class Tool:
    name: str        # display name
    binary: str      # binary checked by shutil.which()
    apt: str         # apt install command
    pip: str         # pip install spec (empty string if not needed)
    critical: bool   # True = warn loudly on startup if missing
    fallback: bool   # True = stdlib manual fallback available
    answers: tuple   # questions this tool can answer (from intelligence.py)


REGISTRY: dict[str, Tool] = {
    "nmap": Tool(
        name="nmap",
        binary="nmap",
        apt="apt install -y nmap",
        pip="",
        critical=True,
        fallback=True,
        answers=(
            "is_host_alive",
            "what_ports_open",
            "what_services_on_ports",
            "what_service_on_port",
            "is_ftp_anonymous",
            "is_smb_vulnerable",
            "what_ssh_ciphers",
            "is_web_vulnerable",
            "is_db_default_creds",
        ),
    ),
    "gobuster": Tool(
        name="gobuster",
        binary="gobuster",
        apt="apt install -y gobuster",
        pip="",
        critical=False,
        fallback=True,
        answers=("what_web_paths_exist",),
    ),
    "ffuf": Tool(
        name="ffuf",
        binary="ffuf",
        apt="apt install -y ffuf",
        pip="",
        critical=False,
        fallback=False,
        answers=("what_web_paths_exist",),
    ),
    "dirb": Tool(
        name="dirb",
        binary="dirb",
        apt="apt install -y dirb",
        pip="",
        critical=False,
        fallback=False,
        answers=("what_web_paths_exist",),
    ),
    "masscan": Tool(
        name="masscan",
        binary="masscan",
        apt="apt install -y masscan",
        pip="",
        critical=False,
        fallback=False,
        answers=("what_ports_open",),
    ),
    "sqlmap": Tool(
        name="sqlmap",
        binary="sqlmap",
        apt="apt install -y sqlmap",
        pip="",
        critical=False,
        fallback=False,
        answers=("is_web_vulnerable",),
    ),
    "nikto": Tool(
        name="nikto",
        binary="nikto",
        apt="apt install -y nikto",
        pip="",
        critical=False,
        fallback=True,
        answers=("is_web_vulnerable",),
    ),
    "whatweb": Tool(
        name="whatweb",
        binary="whatweb",
        apt="apt install -y whatweb",
        pip="",
        critical=False,
        fallback=False,
        answers=("what_web_tech",),
    ),
    "hydra": Tool(
        name="hydra",
        binary="hydra",
        apt="apt install -y hydra",
        pip="",
        critical=False,
        fallback=False,
        answers=(),
    ),
    "metasploit": Tool(
        name="metasploit",
        binary="msfconsole",
        apt="apt install -y metasploit-framework",
        pip="",
        critical=False,
        fallback=False,
        answers=(),
    ),
    "zaproxy": Tool(
        name="zaproxy",
        binary="zaproxy",
        apt="apt install -y zaproxy",
        pip="",
        critical=False,
        fallback=False,
        answers=("is_web_vulnerable",),
    ),
    "mitmproxy": Tool(
        name="mitmproxy",
        binary="mitmproxy",
        apt="apt install -y mitmproxy",
        pip="mitmproxy>=10.0.0",
        critical=False,
        fallback=False,
        answers=(),
    ),
    "ssh-audit": Tool(
        name="ssh-audit",
        binary="ssh-audit",
        apt="apt install -y ssh-audit",
        pip="",
        critical=False,
        fallback=False,
        answers=("what_ssh_ciphers",),
    ),
    "enum4linux": Tool(
        name="enum4linux",
        binary="enum4linux",
        apt="apt install -y enum4linux",
        pip="",
        critical=False,
        fallback=False,
        answers=("is_smb_vulnerable",),
    ),
    "netexec": Tool(
        name="netexec",
        binary="netexec",
        apt="apt install -y netexec",
        pip="",
        critical=False,
        fallback=False,
        answers=("is_smb_vulnerable",),
    ),
    "manual_python": Tool(
        name="manual_python",
        binary="python3",
        apt="",
        pip="",
        critical=False,
        fallback=True,
        answers=(
            "is_host_alive",
            "what_ports_open",
            "what_service_on_port",
            "is_ftp_anonymous",
            "what_web_paths_exist",
            "what_web_tech",
        ),
    ),
}


def tools_for_question(question: str) -> list[Tool]:
    """Return all registered tools that can answer the given question."""
    return [t for t in REGISTRY.values() if question in t.answers]


def installed_tools_for_question(question: str) -> list[Tool]:
    """Return only installed tools that can answer the given question."""
    import shutil
    return [
        t for t in tools_for_question(question)
        if shutil.which(t.binary)
    ]
