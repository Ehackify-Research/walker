"""
Scope management for the Walker Agent.

Loads an allow-list of authorized targets from scope.json and validates
every tool invocation against it before any subprocess is run. This is a
deliberate control: it ensures the agent (or an LLM driving it) cannot be
redirected at an out-of-scope host, whether by user mistake or by an
injected instruction from scanned content.

Usage:
    Create a `scope.json` file next to this module, e.g.:

    {
        "authorized_targets": [
            "192.168.56.0/24",
            "testphp.vulnweb.com",
            "localhost"
        ],
        "engagement_name": "Example VAPT Engagement",
        "authorized_by": "you@example.com",
        "notes": "Only test hosts listed above. Update before each engagement."
    }
"""

import ipaddress
import json
import os
import socket
import time
from pathlib import Path

SCOPE_FILE = Path(__file__).parent / "scope.json"

# ── DNS resolution cache (TTL-based) ────────────────────────────────
# Avoids hammering DNS when the same host is checked repeatedly during
# a scan_all run.  Entries expire after _DNS_CACHE_TTL seconds.
_DNS_CACHE_TTL = 300  # 5 minutes
_dns_cache: dict[str, tuple[set[str], float]] = {}  # host -> (ips, timestamp)


def _resolve_host(host: str) -> set[str]:
    """
    Best-effort DNS resolution.  Returns a set of IP address strings
    that *host* resolves to, or an empty set if resolution fails.

    Results are cached for ``_DNS_CACHE_TTL`` seconds.
    """
    now = time.monotonic()
    cached = _dns_cache.get(host)
    if cached and (now - cached[1]) < _DNS_CACHE_TTL:
        return cached[0]

    try:
        results = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = {r[4][0] for r in results}
    except (socket.gaierror, OSError):
        ips = set()

    _dns_cache[host] = (ips, now)
    return ips


class ScopeError(ValueError):
    """Raised when a target is not in the authorized scope list."""


def _load_scope() -> dict:
    if not SCOPE_FILE.exists():
        raise ScopeError(
            f"No scope.json found at {SCOPE_FILE}. "
            "Create one listing authorized targets before running any scans. "
            "Refusing to run against an unbounded/unknown scope."
        )
    with open(SCOPE_FILE, "r") as f:
        return json.load(f)


def _save_scope(scope: dict) -> None:
    """Write the scope dict back to scope.json (pretty-printed)."""
    with open(SCOPE_FILE, "w") as f:
        json.dump(scope, f, indent=2)
        f.write("\n")


def _extract_host_for_scope(target: str) -> str:
    """
    Defense-in-depth host extraction.

    Even though individual tools should already extract the hostname
    before calling ``assert_in_scope()``, we do it again here so a
    forgotten extraction in any single tool can never bypass scope.
    """
    # Import locally to avoid circular imports
    from tools.helpers import extract_host
    return extract_host(target)


def _host_in_scope(host: str, authorized: list[str]) -> bool:
    # exact match (hostname or IP)
    if host in authorized:
        return True

    # try IP/CIDR matching
    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        host_ip = None

    for entry in authorized:
        # strip protocol/port from authorized entries too (defence-in-depth)
        clean_entry = entry
        if "://" in entry:
            clean_entry = entry.split("://", 1)[-1].split("/")[0].split(":")[0]
        elif "/" not in entry:
            clean_entry = entry.split(":")[0]

        if host_ip is not None:
            try:
                if "/" in entry:
                    if host_ip in ipaddress.ip_network(entry, strict=False):
                        return True
                else:
                    if host_ip == ipaddress.ip_address(clean_entry):
                        return True
            except ValueError:
                continue
        else:
            # hostname suffix match, e.g. authorized "example.com" covers "www.example.com"
            if host == clean_entry or host.endswith("." + clean_entry):
                return True

    # ── DNS-based resolution fallback ───────────────────────────────
    # If literal matching failed, try resolving the host to its IPs
    # and checking those against the authorized list (and vice-versa).
    # This handles the case where scope.json lists "example.com" but
    # the tool was called with the IP, or the other way around.
    #
    # This is best-effort: if DNS fails, we simply don't match.

    if host_ip is not None:
        # Host is an IP — try reverse: resolve each authorized *hostname*
        # entry and see if any of them point to this IP.
        for entry in authorized:
            clean_entry = entry
            if "://" in entry:
                clean_entry = entry.split("://", 1)[-1].split("/")[0].split(":")[0]
            elif "/" not in entry:
                clean_entry = entry.split(":")[0]

            # Skip entries that are already IPs or CIDRs (handled above)
            try:
                ipaddress.ip_address(clean_entry)
                continue
            except ValueError:
                pass
            if "/" in entry:
                continue

            # clean_entry is a hostname — resolve it
            resolved_ips = _resolve_host(clean_entry)
            if str(host_ip) in resolved_ips:
                return True
    else:
        # Host is a hostname — resolve it to IPs and check those
        # against IP/CIDR entries in the authorized list.
        resolved_ips = _resolve_host(host)
        for resolved_ip_str in resolved_ips:
            try:
                resolved_ip = ipaddress.ip_address(resolved_ip_str)
            except ValueError:
                continue
            for entry in authorized:
                clean_entry = entry
                if "://" in entry:
                    clean_entry = entry.split("://", 1)[-1].split("/")[0].split(":")[0]
                elif "/" not in entry:
                    clean_entry = entry.split(":")[0]
                try:
                    if "/" in entry:
                        if resolved_ip in ipaddress.ip_network(entry, strict=False):
                            return True
                    else:
                        if resolved_ip == ipaddress.ip_address(clean_entry):
                            return True
                except ValueError:
                    continue

    return False


def assert_in_scope(target: str) -> None:
    """
    Raise ScopeError if `target` is not in the authorized_targets list.
    Call this from every tool before running any subprocess.

    Automatically extracts the bare hostname/IP from URLs so callers
    don't have to remember to do it themselves.
    """
    host = _extract_host_for_scope(target)
    scope = _load_scope()
    authorized = scope.get("authorized_targets", [])
    if not authorized:
        raise ScopeError("scope.json has no authorized_targets defined. Refusing to scan.")

    if not _host_in_scope(host, authorized):
        raise ScopeError(
            f"Target '{host}' (from '{target}') is not in the authorized scope list "
            f"({scope.get('engagement_name', 'current engagement')}). "
            f"Authorized targets: {authorized}. "
            "Add it to scope.json if this is intentional and authorized."
        )


def get_scope_info() -> dict:
    """Return the current scope config (for display/logging purposes)."""
    return _load_scope()


def add_target(target: str) -> str:
    """Add a target to the authorized list. Returns a confirmation message."""
    scope = _load_scope()
    targets = scope.get("authorized_targets", [])
    if target in targets:
        return f"Target '{target}' is already in scope."
    targets.append(target)
    scope["authorized_targets"] = targets
    _save_scope(scope)
    return f"Target '{target}' added to scope."


def remove_target(target: str) -> str:
    """Remove a target from the authorized list. Returns a confirmation message."""
    scope = _load_scope()
    targets = scope.get("authorized_targets", [])
    if target not in targets:
        return f"Target '{target}' is not in scope — nothing to remove."
    targets.remove(target)
    scope["authorized_targets"] = targets
    _save_scope(scope)
    return f"Target '{target}' removed from scope."
