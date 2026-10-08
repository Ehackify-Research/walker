"""WPScan — WordPress vulnerability scanner."""

from config.scope import assert_in_scope
from config.audit import log_action
from tools.helpers import extract_host, safe_run, parse_options, Timer


async def run_wpscan(target: str, options: str | None = None) -> str:
    """
    Run WPScan against an in-scope WordPress target.

    Call this when WhatWeb, Nuclei, or manual inspection identifies a
    WordPress installation. Enumerates users, plugins, themes, and
    known CVEs.
    """
    assert_in_scope(extract_host(target))

    cmd = ["wpscan", "--url", target, "--no-banner"]
    cmd += parse_options(options)

    with Timer() as t:
        output, exit_code = await safe_run(cmd, timeout=300, tool_name="wpscan")

    log_action("wpscan", target, options, output,
               duration_seconds=t.elapsed, exit_code=exit_code)
    return output
