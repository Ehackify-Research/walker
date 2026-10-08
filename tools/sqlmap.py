"""SQLMap — SQL injection testing (confirm-gated)."""

from config.scope import assert_in_scope
from config.audit import log_action
from tools.helpers import extract_host, safe_run, parse_options, Timer


async def run_sqlmap(target: str, options: str | None = None, confirm: bool = False) -> str:
    """
    Run sqlmap against an in-scope target. Requires confirm=True.

    This will NOT run unless the caller explicitly passes confirm=True,
    on top of the target being in scope.json. This is deliberate friction:
    a scan result alone should never be sufficient to trigger this.
    """
    if not confirm:
        return (
            "[!] sqlmap requires explicit confirmation. "
            "Call again with confirm=True if you have verified this target "
            "is in scope and you intend to actively test for SQL injection."
        )

    assert_in_scope(extract_host(target))

    cmd = ["sqlmap", "-u", target, "--batch", "--level=1", "--risk=1"]
    cmd += parse_options(options)

    with Timer() as t:
        output, exit_code = await safe_run(cmd, timeout=600, tool_name="sqlmap")

    log_action("sqlmap", target, options, output,
               duration_seconds=t.elapsed, exit_code=exit_code)
    return output
