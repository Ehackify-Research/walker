"""Hydra — network brute-force tool (confirm-gated)."""

from config.scope import assert_in_scope
from config.audit import log_action
from tools.helpers import extract_host, safe_run, parse_options, Timer


async def run_hydra(
    target: str,
    service: str,
    options: str | None = None,
    confirm: bool = False,
) -> str:
    """
    Run Hydra brute-force attack against an in-scope target service.
    Requires confirm=True.

    Example usage:
        run_hydra("10.10.10.202", "ssh",
                  options="-l admin -P /usr/share/wordlists/rockyou.txt",
                  confirm=True)

    This is a destructive/intrusive operation — the confirm gate ensures
    the operator has reviewed the situation and deliberately chosen to
    run it.
    """
    if not confirm:
        return (
            "[!] Hydra requires explicit confirmation. "
            "Call again with confirm=True if you have verified this target "
            "is in scope and you intend to brute-force credentials."
        )

    assert_in_scope(extract_host(target))

    cmd = ["hydra"] + parse_options(options) + [target, service]

    with Timer() as t:
        output, exit_code = await safe_run(cmd, timeout=600, tool_name="hydra")

    log_action("hydra", target, f"service={service} {options}",
               output, duration_seconds=t.elapsed, exit_code=exit_code)
    return output
