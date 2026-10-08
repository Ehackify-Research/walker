"""
Shared helpers for Walker Agent tool wrappers.

Centralises the boilerplate that every tool needs — host extraction,
subprocess execution with proper error handling, option parsing, and
tool-availability checking — so each wrapper is short, consistent, and
free of the bugs that crept in when this logic was copy-pasted.
"""

import os
import shlex
import shutil
import asyncio
import time
from urllib.parse import urlparse


def extract_host(target: str) -> str:
    """
    Extract a bare hostname or IP from *any* target string.

    Handles:
        "10.10.10.202"                   -> "10.10.10.202"
        "http://10.10.10.202:80/path"    -> "10.10.10.202"
        "https://example.com"            -> "example.com"
        "example.com:8080"               -> "example.com"
        "http://example.com/FUZZ"        -> "example.com"

    Every tool should call this before passing a target to
    ``assert_in_scope()`` so scope checking never fails due to
    protocol prefixes, port suffixes, or path segments.
    """
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or parsed.netloc
    else:
        # bare host, possibly with port: "host:port"
        host = target.split("/")[0].split(":")[0]

    return host.strip() if host else target.strip()


async def safe_run(
    cmd: list[str],
    timeout: int = 300,
    tool_name: str | None = None,
) -> tuple[str, int | None]:
    """
    Run an asynchronous subprocess command with consistent error handling.

    Returns:
        (output_text, exit_code)

    ``exit_code`` is ``None`` when the tool was not found or timed out.
    This function never raises — it always returns a human-readable
    error string so the MCP server stays up.
    """
    label = tool_name or cmd[0]
    if not check_tool_exists(cmd[0]):
        return (
            f"[!] {label} not found. "
            f"Please install {label} and ensure it is in PATH."
        ), None

    try:
        # Create subprocess execution asynchronously
        proc = await asyncio.create_subprocess_exec(
            cmd[0],
            *cmd[1:],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            # Wait for execution with timeout
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            exit_code = proc.returncode
            output = stdout.decode(errors="ignore")
            err_output = stderr.decode(errors="ignore")

            if exit_code != 0 and err_output:
                output = (output or "") + f"\n[!] {label} stderr:\n{err_output}"
            output = output or f"[!] {label} returned no output."
            return output, exit_code

        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()
            return f"[!] {label} scan timed out after {timeout}s.", None

    except Exception as e:
        return f"[!] Error executing {label}: {e}", None


def parse_options(options: str | None) -> list[str]:
    """
    Split an options string into a list, using ``shlex.split`` where
    possible (handles quoted arguments) and falling back to ``.split()``
    for malformed input.  Returns an empty list when *options* is falsy.
    """
    if not options:
        return []
    try:
        return shlex.split(options)
    except ValueError:
        return options.split()


def check_tool_exists(name: str) -> bool:
    """Return ``True`` if *name* is found on ``PATH``."""
    return shutil.which(name) is not None


def check_asset_exists(path: str) -> bool:
    """Return ``True`` if the asset file at *path* exists and is readable."""
    from pathlib import Path
    p = Path(path)
    return p.is_file() and os.access(p, os.R_OK)


# ── Common asset paths ──────────────────────────────────────────────

DEFAULT_WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/rockyou.txt",
]


# ── Timing helper for audit enrichment ──────────────────────────────

class Timer:
    """Context manager that records elapsed wall-clock seconds."""

    def __init__(self) -> None:
        self.elapsed: float = 0.0

    def __enter__(self) -> "Timer":
        self._start = time.monotonic()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.elapsed = round(time.monotonic() - self._start, 2)

