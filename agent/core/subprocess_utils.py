import os
import shutil
import subprocess

# Full system PATH — ensures tools installed in standard locations are found
# even when the process inherits a stripped environment (e.g. systemd service)
_FULL_PATH = (
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
    ":/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"
)


def get_env() -> dict:
    """Return os.environ with a guaranteed full PATH prepended."""
    env = os.environ.copy()
    env["PATH"] = _FULL_PATH + ":" + env.get("PATH", "")
    return env


def run_tool(command: list, timeout: int = 120) -> tuple[str, str, int]:
    """
    Safely run an external binary as a subprocess.

    - Resolves the binary to its full path using the enriched PATH so the
      call succeeds even in stripped environments (systemd, sudo, etc.)
    - Never uses text=True — always decodes manually with error replacement
    - Never uses capture_output=True — uses PIPE explicitly
    - Always passes env=get_env() so child processes inherit full PATH
    - Uses /tmp as cwd to avoid working-directory surprises

    Returns (stdout, stderr, returncode).
    On timeout or binary-not-found returns ("", error_message, 1).
    """
    env = get_env()

    binary = shutil.which(command[0], path=env["PATH"])
    if not binary:
        return "", f"{command[0]} not found in PATH", 1

    command = list(command)
    command[0] = binary

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=timeout,
            cwd="/tmp",
        )
        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
        return stdout, stderr, result.returncode

    except subprocess.TimeoutExpired:
        return "", f"{command[0]} timed out after {timeout}s", 1

    except Exception as e:
        return "", str(e), 1


def tool_exists(binary: str) -> bool:
    """Return True if binary is findable on the enriched PATH."""
    return shutil.which(binary, path=get_env()["PATH"]) is not None
