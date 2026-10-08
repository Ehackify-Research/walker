"""Nikto — web vulnerability scanner."""

from config.scope import assert_in_scope
from config.audit import log_action
from tools.helpers import extract_host, safe_run, parse_options, Timer


async def run_nikto(target: str, options: str | None = None) -> str:
    """Run nikto web vulnerability scan against an in-scope target."""
    assert_in_scope(extract_host(target))

    cmd = ["nikto", "-h", target] + parse_options(options)

    with Timer() as t:
        output, exit_code = await safe_run(cmd, timeout=300, tool_name="nikto")

    log_action("nikto", target, options, output,
               duration_seconds=t.elapsed, exit_code=exit_code)
    return output
