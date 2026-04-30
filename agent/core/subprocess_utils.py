from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
import rich.box


_FULL_PATH = (
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
    ":/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"
)

_console = Console()


class ToolNotFoundError(Exception):
    pass


@dataclass
class TransparentResult:
    command: list
    raw_output: str
    clean_output: str
    returncode: int
    duration: float = 0.0
    timed_out: bool = False
    tool_not_found: bool = False
    error: str = ""


_NOISE_PATTERNS: dict[str, list[str]] = {
    "nmap": [
        "Starting Nmap",
        "NSE: Loaded", "NSE: Script Pre", "NSE: Starting", "NSE: Finished",
        "Initiating", "Completed", "Read data files from",
        "Nmap done:", "Stats:", "Scanning",
    ],
    "gobuster": [
        "===============", "Gobuster v",
        "[+] Url:", "[+] Method:", "[+] Threads:", "[+] Wordlist:",
        "[+] Negative", "[+] User Agent", "[+] Timeout:",
        "Starting gobuster", "Finished:", "Progress:",
    ],
    "nikto": [
        "- Nikto v", "+ Target IP:", "+ Target Hostname:",
        "+ Target Port:", "+ Start Time:", "+ End Time:", "- Testing for",
    ],
    "sqlmap": [
        "sqlmap/", "all requests", "fetched data logged",
        "you can find results", "shutting down at",
    ],
    "hydra": [
        "Hydra v", "[DATA]", "[STATUS]", "[ATTEMPT]",
        "[VERBOSE]", "[RE-ATTEMPT]",
    ],
}


class TransparentRunner:
    """
    Runs external tools transparently — user sees stdout+stderr live in
    the terminal, agent receives both raw and noise-filtered output for
    parsing and evidence saving.
    """

    def __init__(self):
        self._console = _console

    def get_env(self) -> dict:
        env = os.environ.copy()
        env["PATH"] = _FULL_PATH + ":" + env.get("PATH", "")
        return env

    def _resolve_binary(self, cmd: str) -> str:
        env = self.get_env()
        binary = shutil.which(cmd, path=env["PATH"])
        if binary:
            return binary
        for fallback_dir in (
            "/usr/bin", "/usr/local/bin",
            "/usr/sbin", "/usr/local/sbin", "/snap/bin",
        ):
            candidate = Path(fallback_dir) / cmd
            if candidate.is_file():
                return str(candidate)
        raise ToolNotFoundError(f"{cmd} not found in PATH or standard locations")

    def _is_noise(self, line: str, tool: str) -> bool:
        stripped = line.strip()
        if not stripped:
            return True
        if stripped.startswith("=") or stripped.startswith("----"):
            return True
        for pattern in _NOISE_PATTERNS.get(tool, []):
            if pattern in stripped:
                return True
        return False

    def run(
        self,
        command: list,
        label: str = "",
        timeout: int = 120,
        filter_noise: bool = True,
    ) -> TransparentResult:
        tool_name = Path(str(command[0])).name

        try:
            binary = self._resolve_binary(str(command[0]))
        except ToolNotFoundError as e:
            return TransparentResult(
                command=command, raw_output="", clean_output="",
                returncode=1, tool_not_found=True, error=str(e),
            )

        full_command = list(command)
        full_command[0] = binary

        cmd_display = " ".join(str(p) for p in command)
        self._console.print(
            Panel(
                f"[bold yellow]⚡ {cmd_display}[/bold yellow]",
                box=rich.box.DOUBLE,
                border_style="dim blue",
                padding=(0, 1),
            )
        )

        env = self.get_env()
        start = time.monotonic()
        lines_raw: list[str] = []
        lines_clean: list[str] = []
        timed_out = False

        try:
            proc = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                cwd="/tmp",
            )

            def _read():
                for raw in proc.stdout:
                    line = raw.decode("utf-8", errors="replace").rstrip("\n\r")
                    lines_raw.append(line)
                    self._console.print(f"[dim]{line}[/dim]")
                    if not filter_noise or not self._is_noise(line, tool_name):
                        lines_clean.append(line)

            reader = threading.Thread(target=_read, daemon=True)
            reader.start()

            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                timed_out = True

            reader.join(timeout=5)
            elapsed = time.monotonic() - start
            rc = proc.returncode if proc.returncode is not None else 1

            if timed_out:
                self._console.print(f"[yellow]⏱ timed out after {timeout}s[/yellow]")
            else:
                icon = "✅" if rc == 0 else "❌"
                self._console.print(f"{icon} complete in {elapsed:.1f}s")

            return TransparentResult(
                command=command,
                raw_output="\n".join(lines_raw),
                clean_output="\n".join(lines_clean),
                returncode=rc,
                duration=elapsed,
                timed_out=timed_out,
            )

        except Exception as e:
            elapsed = time.monotonic() - start
            return TransparentResult(
                command=command, raw_output="", clean_output="",
                returncode=1, duration=elapsed, error=str(e),
            )

    def install_tool(self, tool_name: str, apt_package: str) -> bool:
        self._console.print(
            Panel(
                f"[bold yellow]⚠ {tool_name} not installed[/bold yellow]\n"
                f"Required for: {tool_name} operations\n"
                f"Install with: [bold]apt install {apt_package}[/bold]\n\n"
                f"Install now? [y/n]",
                box=rich.box.ROUNDED,
                border_style="yellow",
            )
        )
        try:
            answer = self._console.input("→ ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        if answer != "y":
            return False

        result = self.run(
            ["apt", "install", "-y", apt_package],
            label=f"Installing {apt_package}",
            timeout=300,
            filter_noise=False,
        )
        installed = result.returncode == 0
        icon = "✅" if installed else "❌"
        msg = "installed successfully" if installed else f"failed (exit {result.returncode})"
        self._console.print(f"{icon} {tool_name} {msg}")
        return installed


# ── Module-level singleton ────────────────────────────────────────────────────
runner = TransparentRunner()


# ── Backward-compat (used by methodology.py internal calls — stays silent) ────

def get_env() -> dict:
    return runner.get_env()


def tool_exists(binary: str) -> bool:
    return shutil.which(binary, path=get_env()["PATH"]) is not None


def run_tool(command: list, timeout: int = 120) -> tuple[str, str, int]:
    """Silent subprocess — internal callers only, no terminal output."""
    env = get_env()
    binary = shutil.which(command[0], path=env["PATH"])
    if not binary:
        return "", f"{command[0]} not found in PATH", 1
    cmd = list(command)
    cmd[0] = binary
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, timeout=timeout, cwd="/tmp",
        )
        return (
            result.stdout.decode("utf-8", errors="replace"),
            result.stderr.decode("utf-8", errors="replace"),
            result.returncode,
        )
    except subprocess.TimeoutExpired:
        return "", f"{command[0]} timed out after {timeout}s", 1
    except Exception as e:
        return "", str(e), 1
