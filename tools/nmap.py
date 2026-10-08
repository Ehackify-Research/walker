"""Nmap — port / service discovery scan."""

from config.scope import assert_in_scope
from config.audit import log_action
from tools.helpers import extract_host, safe_run, parse_options, Timer


async def run_nmap(target: str, options: str = "-sV -Pn") -> str:
    """Run nmap against an in-scope target and return raw output."""
    assert_in_scope(extract_host(target))

    cmd = ["nmap"] + parse_options(options) + [target]

    with Timer() as t:
        output, exit_code = await safe_run(cmd, timeout=120, tool_name="nmap")

    log_action("nmap", target, options, output,
               duration_seconds=t.elapsed, exit_code=exit_code)
    return output
