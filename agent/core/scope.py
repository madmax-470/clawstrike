import ipaddress
import socket
from rich.console import Console

console = Console()


class ScopeManager:
    """
    Enforces engagement scope. Every tool call target is validated
    before execution. Out-of-scope targets are hard-refused.
    """

    def __init__(self):
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._raw_entries: list[str] = []  # for display

    # ── public API ────────────────────────────────────────────────────────────

    def set_scope(self, *entries: str) -> list[str]:
        """
        Set scope from one or more strings.
        Each entry can be: CIDR (10.0.0.0/8), single IP (192.168.1.1),
        or hostname (target.local).
        Returns list of errors for any entry that could not be parsed.
        """
        self._networks.clear()
        self._raw_entries.clear()
        errors = []

        for entry in entries:
            entry = entry.strip().rstrip(",")
            if not entry:
                continue
            try:
                net = ipaddress.ip_network(entry, strict=False)
                self._networks.append(net)
                self._raw_entries.append(entry)
            except ValueError:
                # try resolving as hostname
                try:
                    ip = socket.gethostbyname(entry)
                    net = ipaddress.ip_network(ip, strict=False)
                    self._networks.append(net)
                    self._raw_entries.append(f"{entry} ({ip})")
                except (socket.gaierror, ValueError):
                    errors.append(entry)

        return errors

    def clear(self):
        self._networks.clear()
        self._raw_entries.clear()

    def is_set(self) -> bool:
        return len(self._networks) > 0

    def get_entries(self) -> list[str]:
        return list(self._raw_entries)

    def is_in_scope(self, target: str) -> tuple[bool, str]:
        """
        Check whether target is within the defined scope.
        Returns (True, "") if in scope or scope not set.
        Returns (False, reason) if out of scope.
        """
        if not self.is_set():
            return True, ""

        ip_str = _resolve_target(target)
        if ip_str is None:
            return False, f"could not resolve '{target}' to an IP address"

        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"'{ip_str}' is not a valid IP address"

        for net in self._networks:
            if ip in net:
                return True, ""

        scope_str = ", ".join(self._raw_entries)
        return False, f"{ip_str} is not within defined scope [{scope_str}]"

    def show(self) -> str:
        if not self.is_set():
            return "No scope defined. All targets allowed (use 'scope <cidr>' to restrict)."
        return "Scope: " + ", ".join(self._raw_entries)


# ── helpers ───────────────────────────────────────────────────────────────────

def _resolve_target(target: str) -> str | None:
    """
    Extract and resolve the IP/hostname from a target string.
    Handles: bare IP, IP:port, http://host/path, hostname.
    """
    # strip scheme
    for scheme in ("https://", "http://"):
        if target.startswith(scheme):
            target = target[len(scheme):]

    # strip path
    target = target.split("/")[0]

    # strip port
    if ":" in target and not target.startswith("["):
        target = target.rsplit(":", 1)[0]

    # already an IP?
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # resolve hostname
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None
