"""SearchSploit — offline Exploit-DB search (informational, no scope gate)."""

from config.audit import log_action
from tools.helpers import safe_run, parse_options, Timer

# searchsploit queries a local database — it doesn't touch any remote
# target, so there's no scope enforcement, just like whois.


async def run_searchsploit(query: str, options: str | None = None) -> str:
    """
    Search the local Exploit-DB database for known exploits matching *query*.

    Useful after nmap identifies specific service versions — e.g.
    ``searchsploit("Apache 2.4.7")`` or ``searchsploit("vsftpd 2.3.4")``.
    """
    cmd = ["searchsploit", query] + parse_options(options)

    with Timer() as t:
        output, exit_code = await safe_run(cmd, timeout=30, tool_name="searchsploit")

    log_action("searchsploit", query, options, output,
               duration_seconds=t.elapsed, exit_code=exit_code)
    return output
