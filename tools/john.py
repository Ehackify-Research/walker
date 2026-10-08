"""John the Ripper — offline password hash cracker.

Hash files MUST reside under the project's ``scans/hashes/`` directory.
This prevents prompt-injection or LLM hallucination from being used to
read arbitrary system files (e.g. ``/etc/shadow``).
"""

from config.audit import log_action
from tools.helpers import safe_run, parse_options, Timer
from tools.path_safety import assert_safe_path, PathSafetyError


async def run_john(hashfile: str, options: str | None = None) -> str:
    """
    Run John the Ripper against a hash file.

    The *hashfile* path is sandboxed to ``scans/hashes/`` — any attempt
    to reference files outside that directory (via ``../`` traversal,
    absolute paths, or symlinks) will be rejected before ``john`` is
    invoked.

    No network-scope enforcement (this is a local-only tool).
    """
    try:
        safe_hashfile = assert_safe_path(hashfile)
    except PathSafetyError as e:
        return (
            f"[!] Blocked: {e}\n"
            f"Place your hash files in the scans/hashes/ directory and "
            f"reference them by filename only (e.g. 'target_hashes.txt')."
        )

    cmd = ["john", safe_hashfile] + parse_options(options)

    with Timer() as t:
        output, exit_code = await safe_run(cmd, timeout=600, tool_name="john")

    log_action("john", safe_hashfile, options, output,
               duration_seconds=t.elapsed, exit_code=exit_code)
    return output
