"""Nuclei — template-based vulnerability scanner."""

from config.scope import assert_in_scope
from config.audit import log_action
from tools.helpers import extract_host, safe_run, parse_options, Timer

DEFAULT_TEMPLATES = ["cves/", "exposures/", "misconfiguration/"]


async def run_nuclei(target: str, options: str | None = None) -> str:
    """Run nuclei template-based scan against an in-scope target."""
    assert_in_scope(extract_host(target))

    opts_list = parse_options(options)

    templates_requested = any(
        tok == "-t" or tok.startswith("-t=") or tok.startswith("--template")
        for tok in opts_list
    )
    if not templates_requested:
        for tpl in DEFAULT_TEMPLATES:
            opts_list.extend(["-t", tpl])

    cmd = ["nuclei", "-u", target] + opts_list

    with Timer() as t:
        output, exit_code = await safe_run(cmd, timeout=300, tool_name="nuclei")

    log_action("nuclei", target, options, output,
               duration_seconds=t.elapsed, exit_code=exit_code)
    return output
