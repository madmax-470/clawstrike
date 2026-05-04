from __future__ import annotations

import os
import ssl as ssl_module
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


def build_base_url(target: str, port: int) -> str:
    """
    Build correct base URL.
    - Port 80  → http://target      (no port suffix)
    - Port 443 → https://target     (no port suffix)
    - Any other port → http://target:port
    Strips any existing scheme or :port from target before building.
    """
    for prefix in ("https://", "http://"):
        if target.startswith(prefix):
            target = target[len(prefix):]
            break
    clean_target = target.split(':')[0]

    if port == 80:
        return f"http://{clean_target}"
    elif port == 443:
        return f"https://{clean_target}"
    elif port in (8443, 8444):
        return f"https://{clean_target}:{port}"
    else:
        return f"http://{clean_target}:{port}"


def load_wordlist(path: str) -> list:
    paths = []
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if not line.startswith("/"):
                    line = "/" + line
                paths.append(line)
    except Exception as e:
        console.print(f"[red]Wordlist load failed: {e}[/red]")
    return paths


def _build_opener(use_ssl: bool):
    class NoRedirect(urllib.request.HTTPErrorProcessor):
        def http_response(self, request, response):
            return response
        https_response = http_response

    if use_ssl:
        ctx = ssl_module.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_module.CERT_NONE
        return urllib.request.build_opener(
            NoRedirect,
            urllib.request.HTTPSHandler(context=ctx),
        )
    return urllib.request.build_opener(NoRedirect)


def check_path(args: tuple):
    base_url, path, timeout, use_ssl = args
    url = base_url + path
    try:
        opener = _build_opener(use_ssl)
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 ClawStrike/0.1"
                ),
                "Accept": "*/*",
                "Connection": "close",
            },
        )
        response = opener.open(req, timeout=timeout)
        code = response.getcode()
        if code != 404:
            return path, code
    except urllib.error.HTTPError as e:
        if e.code != 404:
            return path, e.code
    except Exception:
        pass
    return None


def detect_wildcard(base_url: str, use_ssl: bool, timeout: int) -> bool:
    """Return True if server responds 200 to a random nonexistent path."""
    fake = f"/clawstrike_nonexistent_{os.urandom(4).hex()}"
    result = check_path((base_url, fake, timeout, use_ssl))
    return result is not None and result[1] == 200


def scan(
    target: str,
    port: int = 80,
    ssl: bool = False,
    wordlist: str = None,
    threads: int = 20,
    timeout: int = 5,
) -> tuple[dict, int]:
    """
    Scan target for web paths.
    Returns (found_dict, total_paths_scanned).
    found_dict maps path → HTTP status code.
    """
    use_ssl = ssl or port in (443, 8443, 8444)
    base_url = build_base_url(target, port)

    if not wordlist:
        console.print("[yellow]⚠ No wordlist — skipping web scan[/yellow]")
        return {}, 0

    if not os.path.exists(wordlist):
        console.print(f"[red]Wordlist not found: {wordlist}[/red]")
        console.print("[dim]Check path and try again[/dim]")
        return {}, 0

    console.print(f"[dim]wordlist: {wordlist}[/dim]")
    paths = load_wordlist(wordlist)
    total = len(paths)
    console.print(f"[dim]loaded {total} paths[/dim]")

    if detect_wildcard(base_url, use_ssl, timeout):
        console.print(
            "[yellow]⚠ Wildcard response detected — "
            "server returns 200 for all paths. "
            "Results may include false positives.[/yellow]"
        )

    args = [(base_url, p, timeout, use_ssl) for p in paths]

    with Progress(
        SpinnerColumn(),
        TextColumn("[dim]{task.description}[/dim]"),
        transient=True,
    ) as progress:
        task = progress.add_task(
            f"scanning {total} paths on {target}...",
            total=None,
        )
        with ThreadPoolExecutor(max_workers=threads) as pool:
            results = list(pool.map(check_path, args))
        progress.update(task, description="scan complete — checking results")

    found = {}
    for result in results:
        if result:
            path, code = result
            found[path] = code

    return found, total


def classify_status(code: int) -> str:
    mapping = {
        200: "accessible",
        204: "no content",
        301: "redirect",
        302: "redirect",
        307: "redirect",
        401: "auth required",
        403: "forbidden",
        405: "method not allowed",
        500: "server error",
    }
    return mapping.get(code, f"status {code}")


def format_for_agent(target: str, results: dict, total_scanned: int = 0) -> str:
    scanned_str = f"Scanned {total_scanned} paths — " if total_scanned else ""

    if not results:
        return f"{scanned_str}no accessible paths found on {target}"

    lines = [f"{scanned_str}found {len(results)} result(s) on {target}:\n"]

    priority = {200: 0, 401: 1, 403: 2, 301: 3, 302: 4, 405: 5}
    sorted_paths = sorted(
        results.items(),
        key=lambda x: priority.get(x[1], 9),
    )

    for path, code in sorted_paths:
        label = classify_status(code)
        interesting = "  ⚠ INTERESTING" if code in (200, 401, 403) else ""
        lines.append(f"  {path:<35} [{code} {label}]{interesting}")

    return "\n".join(lines)
