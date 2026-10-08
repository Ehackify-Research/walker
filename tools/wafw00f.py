"""wafw00f — Web Application Firewall (WAF) detection."""

from config.scope import assert_in_scope
from config.audit import log_action
from tools.helpers import extract_host, safe_run, parse_options, Timer


async def run_wafw00f(target: str, options: str | None = None) -> str:
    """
    Run wafw00f against an in-scope target to detect WAF presence.

    Knowing whether a WAF is in front of the target is important context:
    it affects how subsequent scanners behave and whether results may be
    filtered/misleading.
    """
    assert_in_scope(extract_host(target))

    cmd = ["wafw00f", target] + parse_options(options)

    with Timer() as t:
        output, exit_code = await safe_run(cmd, timeout=60, tool_name="wafw00f")

    log_action("wafw00f", target, options, output,
               duration_seconds=t.elapsed, exit_code=exit_code)
    return output
