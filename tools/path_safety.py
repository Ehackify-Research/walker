"""
Path safety utilities for Walker Agent.

Provides a reusable sandboxing function that prevents path-traversal
attacks (``../../etc/shadow``) and symlink escapes.  Every tool that
accepts a user-supplied filesystem path should call ``assert_safe_path``
before touching the file.
"""

import os
from pathlib import Path

# Default safe root — all user-supplied file paths must resolve inside this.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SAFE_ROOT = _PROJECT_ROOT / "scans" / "hashes"


class PathSafetyError(ValueError):
    """Raised when a file path escapes the allowed sandbox directory."""


def assert_safe_path(
    path: str,
    allowed_root: Path | str = DEFAULT_SAFE_ROOT,
) -> str:
    """
    Validate that *path* resolves to a location inside *allowed_root*.

    Returns the resolved, canonical absolute path as a string so callers
    can use it directly.

    Raises :class:`PathSafetyError` if:
    - The resolved path is outside *allowed_root* (catches ``../`` and
      symlink escapes).
    - The path is an absolute path that doesn't start with *allowed_root*.
    - *allowed_root* itself does not exist (misconfiguration guard).

    Example::

        safe = assert_safe_path("hashes.txt")
        # -> "/home/kali/…/walker_agent/scans/hashes/hashes.txt"

        assert_safe_path("../../etc/shadow")
        # -> PathSafetyError
    """
    allowed_root = Path(allowed_root).resolve()

    if not allowed_root.exists():
        raise PathSafetyError(
            f"Safe root directory '{allowed_root}' does not exist. "
            f"Create it before using this tool: mkdir -p {allowed_root}"
        )

    candidate = Path(path)

    # If the user gave a relative path, anchor it inside the safe root.
    if not candidate.is_absolute():
        candidate = allowed_root / candidate

    # Resolve symlinks and ".." segments to get the real, canonical path.
    resolved = candidate.resolve()

    # The critical check: is the resolved path still under the safe root?
    try:
        resolved.relative_to(allowed_root)
    except ValueError:
        raise PathSafetyError(
            f"Path '{path}' resolves to '{resolved}', which is outside the "
            f"allowed directory '{allowed_root}'. This looks like a path "
            f"traversal attempt and has been blocked."
        )

    return str(resolved)
