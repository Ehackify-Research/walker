"""WHOIS — domain registration lookup (OSINT, no scope gate)."""

from config.audit import log_action
from tools.helpers import safe_run, Timer

# whois is informational/OSINT, not an active scan against infrastructure,
# so we don't gate it on scope.json the same way — but we still log it.


async def run_whois(domain: str) -> str:
    """Perform a WHOIS lookup on a domain."""
    with Timer() as t:
        output, exit_code = await safe_run(
            ["whois", domain], timeout=30, tool_name="whois",
        )

    log_action("whois", domain, None, output,
               duration_seconds=t.elapsed, exit_code=exit_code)
    return output
