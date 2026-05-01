from __future__ import annotations

import os
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

WORDLIST_PATHS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/wordlists/dirb/small.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/big.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]


def find_wordlist() -> str | None:
    for path in WORDLIST_PATHS:
        if os.path.exists(path):
            return path
    return None


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


def check_path(args: tuple):
    base_url, path, timeout = args
    url = base_url + path
    try:
        class NoRedirect(urllib.request.HTTPErrorProcessor):
            def http_response(self, request, response):
                return response
            https_response = http_response

        opener = urllib.request.build_opener(NoRedirect)
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 ClawStrike/0.1",
                "Accept": "*/*",
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


def scan(
    target: str,
    port: int = 80,
    ssl: bool = False,
    wordlist: str = None,
    threads: int = 20,
    timeout: int = 5,
) -> dict:
    scheme = "https" if ssl or port == 443 else "http"
    base_url = f"{scheme}://{target}:{port}"

    wl_path = wordlist or find_wordlist()
    if not wl_path:
        console.print(
            "[red]No wordlist found.[/red]\n"
            "Install: apt install dirb seclists wordlists"
        )
        return {}

    console.print(f"[dim]wordlist: {wl_path}[/dim]")
    paths = load_wordlist(wl_path)
    console.print(f"[dim]loaded {len(paths)} paths to check[/dim]")

    args = [(base_url, p, timeout) for p in paths]

    with Progress(
        SpinnerColumn(),
        TextColumn("[dim]{task.description}[/dim]"),
        transient=True,
    ) as progress:
        task = progress.add_task(
            f"scanning {len(paths)} paths on {target}...",
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

    return found


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


def format_for_agent(target: str, results: dict) -> str:
    if not results:
        return f"No accessible paths found on {target}"

    lines = [f"Found {len(results)} web path(s) on {target}:\n"]

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
