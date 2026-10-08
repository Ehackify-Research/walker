"""Dalfox — XSS vulnerability scanner."""

from config.scope import assert_in_scope
from config.audit import log_action
from tools.helpers import extract_host, safe_run, parse_options, Timer


async def run_dalfox(target: str, options: str | None = None) -> str:
    """Run dalfox XSS scan against an in-scope target URL."""
    assert_in_scope(extract_host(target))

    cmd = ["dalfox", "url", target] + parse_options(options)

    with Timer() as t:
        output, exit_code = await safe_run(cmd, timeout=300, tool_name="dalfox")

    log_action("dalfox", target, options, output,
               duration_seconds=t.elapsed, exit_code=exit_code)
    return output
