"""FFUF — web fuzzer."""

from config.scope import assert_in_scope
from config.audit import log_action
from tools.helpers import extract_host, safe_run, parse_options, Timer


async def run_ffuf(target: str, wordlist: str, options: str | None = None) -> str:
    """Run ffuf fuzzing scan against an in-scope target URL."""
    assert_in_scope(extract_host(target))

    if "FUZZ" not in target:
        target = target.rstrip("/") + "/FUZZ"

    cmd = ["ffuf", "-u", target, "-w", wordlist] + parse_options(options)

    with Timer() as t:
        output, exit_code = await safe_run(cmd, timeout=300, tool_name="ffuf")

    log_action("ffuf", target, f"wordlist={wordlist} options={options}",
               output, duration_seconds=t.elapsed, exit_code=exit_code)
    return output
