"""
Lightweight audit logging for the Walker Agent.

Every tool call is appended as a JSON line to audit.log so there's a
record of what was run, against what target, and when. This is standard
practice for VAPT engagements and is also a nice thing to show off in a
portfolio ("the tool logs everything for accountability").
"""

import json
import time
from pathlib import Path

LOG_FILE = Path(__file__).parent / "audit.log"


def log_action(
    tool: str,
    target: str,
    options: str | None,
    result_summary: str,
    duration_seconds: float | None = None,
    exit_code: int | None = None,
) -> None:
    """Append one JSON-line audit record."""
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "tool": tool,
        "target": target,
        "options": options,
        "exit_code": exit_code,
        "duration_seconds": duration_seconds,
        "result_summary": result_summary[:500],
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


def get_recent_logs(n: int = 20) -> list[dict]:
    """Return the last *n* audit log entries (most recent last)."""
    if not LOG_FILE.exists():
        return []
    lines = LOG_FILE.read_text().strip().splitlines()
    entries: list[dict] = []
    for line in lines[-n:]:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries
