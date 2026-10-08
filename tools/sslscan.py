"""SSLScan — SSL/TLS cipher and certificate analysis."""

from config.scope import assert_in_scope
from config.audit import log_action
from tools.helpers import extract_host, safe_run, parse_options, Timer


async def run_sslscan(target: str, options: str | None = None) -> str:
    """
    Run sslscan against an in-scope target to check for weak ciphers,
    expired certificates, and protocol downgrade vulnerabilities.

    Typically run on HTTPS ports (443, 8443, etc.).
    """
    assert_in_scope(extract_host(target))

    # sslscan expects host:port — strip any protocol prefix
    scan_target = target
    if "://" in scan_target:
        scan_target = scan_target.split("://", 1)[1]

    cmd = ["sslscan"] + parse_options(options) + [scan_target]

    with Timer() as t:
        output, exit_code = await safe_run(cmd, timeout=120, tool_name="sslscan")

    log_action("sslscan", target, options, output,
               duration_seconds=t.elapsed, exit_code=exit_code)
    return output
