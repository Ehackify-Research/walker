"""WhatWeb — web technology fingerprinting."""

from config.scope import assert_in_scope
from config.audit import log_action
from tools.helpers import extract_host, safe_run, parse_options, Timer


async def run_whatweb(target: str, options: str | None = None) -> str:
    """
    Run WhatWeb against an in-scope target to identify web technologies,
    CMS platforms, server versions, and plugins.
    """
    assert_in_scope(extract_host(target))

    # Default aggression level 1 (stealthy)
    cmd = ["whatweb", target] + parse_options(options)

    with Timer() as t:
        output, exit_code = await safe_run(cmd, timeout=120, tool_name="whatweb")

    log_action("whatweb", target, options, output,
               duration_seconds=t.elapsed, exit_code=exit_code)
    return output
