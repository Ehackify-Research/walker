"""Burp Suite launcher (confirm-gated)."""

import subprocess

from config.scope import assert_in_scope
from config.audit import log_action
from tools.helpers import extract_host, parse_options, check_tool_exists, Timer


async def run_burpsuite(target: str, options: str | None = None, confirm: bool = False) -> str:
    """Launch Burp Suite against an in-scope target. Requires confirm=True."""
    if not confirm:
        return (
            "[!] Burp Suite requires explicit confirmation. "
            "Call again with confirm=True if you have verified this target "
            "is in scope and intend to use Burp against it."
        )

    assert_in_scope(extract_host(target))

    import os
    exe = os.environ.get("BURP_PATH")
    if not exe:
        for name in ("burpsuite_pro", "burpsuite"):
            if check_tool_exists(name):
                exe = name
                break
    if not exe:
        return "[!] Burp Suite not found. Ensure it's installed and in PATH."

    cmd = [exe] + parse_options(options) + [target]

    with Timer() as t:
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            result = f"[+] Burp Suite started with PID {proc.pid}."
            exit_code = 0
        except Exception as e:
            result = f"[!] Failed to start Burp Suite: {e}"
            exit_code = None

    log_action("burpsuite", target, options, result,
               duration_seconds=t.elapsed, exit_code=exit_code)
    return result
