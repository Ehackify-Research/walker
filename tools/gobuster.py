"""Gobuster — directory / DNS enumeration."""

from config.scope import assert_in_scope
from config.audit import log_action
from tools.helpers import extract_host, safe_run, Timer


async def run_gobuster(target: str, wordlist: str, mode: str = "dir") -> str:
    """Run gobuster directory/dns enumeration against an in-scope target."""
    assert_in_scope(extract_host(target))

    cmd = ["gobuster", mode, "-u", target, "-w", wordlist]

    with Timer() as t:
        output, exit_code = await safe_run(cmd, timeout=180, tool_name="gobuster")

    log_action("gobuster", target, f"mode={mode} wordlist={wordlist}",
               output, duration_seconds=t.elapsed, exit_code=exit_code)
    return output
