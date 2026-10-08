import sys
import asyncio
from mcp.server.fastmcp import FastMCP

# ANSI Escape Codes
CYAN = "\033[96m"
MAGENTA = "\033[95m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

BANNER = f"""{CYAN}{BOLD}
 ██╗  ██╗  ██╗  █████╗  ██╗     ██╗  ██╗███████╗██████╗ 
 ██║  ██║  ██║ ██╔══██╗ ██║     ██║ ██╔╝██╔════╝██╔══██╗
 ██║  ██║  ██║ ███████║ ██║     █████═╝ █████╗  ██████╔╝
 ██║  ██╗  ██║ ██╔══██║ ██║     ██╔═██╗ ██╔══╝  ██╔══██╗
 ╚██████████╔╝ ██║  ██║ ███████╗██║  ██╗███████╗██║  ██║
  ╚═════╝╚═╝   ╚═╝  ╚═╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝{RESET}{YELLOW}
                                              by Jineesh{RESET}
{MAGENTA}         [ VAPT | MODEL CONTEXT PROTOCOL ENGINE ]{RESET}
"""

def print_banner():
    # Write directly to stderr so stdio MCP communication stays clean on stdout
    sys.stderr.write(BANNER + "\n")
    sys.stderr.write(f"{GREEN}[OK]{RESET} Target Scanner Core Initialized\n")
    sys.stderr.write(f"{CYAN}[LOG]{RESET} Listening for MCP Client requests...\n\n")
    sys.stderr.flush()


from config.scope import assert_in_scope, get_scope_info, add_target, remove_target, ScopeError
from config.audit import get_recent_logs
from tools.helpers import check_tool_exists, check_asset_exists, extract_host, DEFAULT_WORDLISTS

# Import all scanning and tool execution functions (now async)
from tools.nmap import run_nmap
from tools.gobuster import run_gobuster
from tools.nikto import run_nikto
from tools.ffuf import run_ffuf
from tools.nuclei import run_nuclei
from tools.dalfox import run_dalfox
from tools.whois import run_whois
from tools.sqlmap import run_sqlmap
from tools.metasploit import run_metasploit
from tools.burpsuite import run_burpsuite
from tools.john import run_john

# New tools
from tools.whatweb import run_whatweb
from tools.wpscan import run_wpscan
from tools.searchsploit import run_searchsploit
from tools.wafw00f import run_wafw00f
from tools.sslscan import run_sslscan
from tools.hydra import run_hydra

from tools.analysis import (
    extract_open_ports,
    build_suggestions_report,
    build_url,
    generate_markdown_report,
    HTTPS_PORTS
)

mcp = FastMCP("Walker Agent")

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


# ---------------------------------------------------------------------------
# Individual recon/scan tools — each runs only when explicitly called
# ---------------------------------------------------------------------------

@mcp.tool()
async def nmap_scan(target: str, options: str = "-sV -Pn") -> str:
    """Run an Nmap scan against a single in-scope target."""
    try:
        return await run_nmap(target, options)
    except ScopeError as e:
        return f"[!] {e}"


@mcp.tool()
async def gobuster_scan(target: str, wordlist: str = DEFAULT_WORDLIST) -> str:
    """Run a Gobuster directory scan against an in-scope web target."""
    try:
        return await run_gobuster(target, wordlist)
    except ScopeError as e:
        return f"[!] {e}"


@mcp.tool()
async def nikto_scan(target: str, options: str | None = None) -> str:
    """Run a Nikto web vulnerability scan against an in-scope target."""
    try:
        return await run_nikto(target, options)
    except ScopeError as e:
        return f"[!] {e}"


@mcp.tool()
async def ffuf_scan(target: str, wordlist: str = DEFAULT_WORDLIST, options: str | None = None) -> str:
    """Run an FFUF fuzzing scan against an in-scope web target."""
    try:
        return await run_ffuf(target, wordlist, options)
    except ScopeError as e:
        return f"[!] {e}"


@mcp.tool()
async def nuclei_scan(target: str, options: str | None = None) -> str:
    """Run a Nuclei template-based scan against an in-scope target."""
    try:
        return await run_nuclei(target, options)
    except ScopeError as e:
        return f"[!] {e}"


@mcp.tool()
async def dalfox_scan(target: str, options: str | None = None) -> str:
    """Run a Dalfox XSS scan against an in-scope target."""
    try:
        return await run_dalfox(target, options)
    except ScopeError as e:
        return f"[!] {e}"


@mcp.tool()
async def whois_lookup(domain: str) -> str:
    """Perform a WHOIS lookup on a domain (informational, no scope gate)."""
    return await run_whois(domain)


@mcp.tool()
async def john_crack(hashfile: str, options: str | None = None) -> str:
    """Run John the Ripper against a local hash file. No scope enforcement."""
    try:
        return await run_john(hashfile, options)
    except Exception as e:
        return f"[!] {e}"


# ---------------------------------------------------------------------------
# New recon/scan tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def whatweb_scan(target: str, options: str | None = None) -> str:
    """Run a WhatWeb technology fingerprinting scan against an in-scope web target."""
    try:
        return await run_whatweb(target, options)
    except ScopeError as e:
        return f"[!] {e}"


@mcp.tool()
async def wpscan_scan(target: str, options: str | None = None) -> str:
    """Run a WPScan WordPress vulnerability scan against an in-scope WordPress target."""
    try:
        return await run_wpscan(target, options)
    except ScopeError as e:
        return f"[!] {e}"


@mcp.tool()
async def searchsploit_query(query: str, options: str | None = None) -> str:
    """Search local Exploit-DB for exploits matching the query (informational, no scope gate)."""
    return await run_searchsploit(query, options)


@mcp.tool()
async def wafw00f_scan(target: str, options: str | None = None) -> str:
    """Run a wafw00f WAF detection scan against an in-scope web target."""
    try:
        return await run_wafw00f(target, options)
    except ScopeError as e:
        return f"[!] {e}"


@mcp.tool()
async def sslscan_scan(target: str, options: str | None = None) -> str:
    """Run an SSLScan cipher/certificate scan against an in-scope target (usually host:port or HTTPS URL)."""
    try:
        return await run_sslscan(target, options)
    except ScopeError as e:
        return f"[!] {e}"


# ---------------------------------------------------------------------------
# Gated/Exploitation tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def sqlmap_scan(target: str, options: str | None = None, confirm: bool = False) -> str:
    """
    Run SQLMap against an in-scope target. Requires confirm=True.
    Use only after manually reviewing scan_all results and deciding
    SQLi testing is warranted and authorized.
    """
    try:
        return await run_sqlmap(target, options, confirm=confirm)
    except ScopeError as e:
        return f"[!] {e}"


@mcp.tool()
async def metasploit_scan(target: str, options: str | None = None, confirm: bool = False) -> str:
    """
    Launch msfconsole against an in-scope target. Requires confirm=True.
    Module selection happens manually inside the Metasploit console —
    this tool only starts the framework.
    """
    try:
        return await run_metasploit(target, options, confirm=confirm)
    except ScopeError as e:
        return f"[!] {e}"


@mcp.tool()
async def burpsuite_scan(target: str, options: str | None = None, confirm: bool = False) -> str:
    """Launch Burp Suite against an in-scope target. Requires confirm=True."""
    try:
        return await run_burpsuite(target, options, confirm=confirm)
    except ScopeError as e:
        return f"[!] {e}"


@mcp.tool()
async def hydra_bruteforce(target: str, service: str, options: str | None = None, confirm: bool = False) -> str:
    """Run Hydra brute-force attack against an in-scope target service. Requires confirm=True."""
    try:
        return await run_hydra(target, service, options, confirm=confirm)
    except ScopeError as e:
        return f"[!] {e}"


# ---------------------------------------------------------------------------
# scan_all — runs the safe recon/scan tools together, then produces an
# informational suggestions report. Runs scanners concurrently to speed up.
# ---------------------------------------------------------------------------

@mcp.tool()
async def scan_all(target: str, wordlist: str = DEFAULT_WORDLIST) -> str:
    """
    Run the full safe scanning battery against an in-scope target:
    nmap -> wafw00f -> gobuster/nikto/ffuf/nuclei/dalfox/whatweb/sslscan concurrently on discovered web ports.

    Returns a single aggregated report with raw tool output plus suggestions.
    This command never invokes sqlmap, metasploit, burpsuite, or hydra.
    """
    try:
        assert_in_scope(target)
    except ScopeError as e:
        return f"[!] {e}"

    report = [f"[+] Starting scan_all against {target}", "\n=== NMAP ==="]
    nmap_out = await run_nmap(target)
    report.append(nmap_out)

    ports = extract_open_ports(nmap_out)
    report.append(f"\n[+] Open ports: {ports['all'] or 'none'}")
    report.append(f"[+] Web ports : {ports['web'] or 'none'}")
    report.append(f"[+] SQL ports : {ports['sql'] or 'none'}")

    if not ports["all"]:
        report.append("\nNo open ports found — stopping here.")
        return "\n".join(report)

    # Run WAF detection early if web ports exist
    if ports["web"]:
        report.append("\n=== WAF DETECTION ===")
        waf_out = await run_wafw00f(target)
        report.append(waf_out)

        # Run web scanners in parallel to maximize speed
        web_tasks = []
        task_info = [] # Keep track of which output corresponds to which tool

        for p in ports["web"]:
            url = build_url(target, p)
            # Add whatweb task
            web_tasks.append(run_whatweb(url))
            task_info.append((url, "whatweb"))

            # Add sslscan task if HTTPS port
            if p in HTTPS_PORTS:
                web_tasks.append(run_sslscan(url))
                task_info.append((url, "sslscan"))

            # Add gobuster task
            web_tasks.append(run_gobuster(url, wordlist))
            task_info.append((url, "gobuster"))

            # Add nikto task
            web_tasks.append(run_nikto(url))
            task_info.append((url, "nikto"))

            # Add ffuf task
            web_tasks.append(run_ffuf(url, wordlist))
            task_info.append((url, "ffuf"))

            # Add nuclei task
            web_tasks.append(run_nuclei(url))
            task_info.append((url, "nuclei"))

            # Add dalfox task
            web_tasks.append(run_dalfox(url))
            task_info.append((url, "dalfox"))

        if web_tasks:
            report.append("\n[+] Running web scanners in parallel...")
            results = await asyncio.gather(*web_tasks)

            # Re-assemble the outputs in a clean sequence in the report
            current_url = None
            for (url, tool), res in zip(task_info, results):
                if url != current_url:
                    current_url = url
                    report.append(f"\n=== WEB TARGET: {url} ===")
                report.append(f"\n[{tool}]")
                report.append(res)

    # informational suggestions only — no auto-exploitation
    report.append(build_suggestions_report(target, ports))

    report.append(
        "\n=== NEXT STEPS (manual, your decision) ===\n"
        "If your engagement scope and rules of engagement allow it, you can "
        "manually run:\n"
        "  - sqlmap_scan(target=..., confirm=True)   # only if SQLi indicators found\n"
        "  - hydra_bruteforce(target=..., service=..., options=..., confirm=True)\n"
        "  - metasploit_scan(target=..., confirm=True)\n"
        "  - burpsuite_scan(target=..., confirm=True)\n"
        "These require explicit confirm=True and will not run automatically."
    )

    return "\n".join(report)


# ---------------------------------------------------------------------------
# Engagement Management & Reporting Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def check_tools() -> str:
    """Check which VAPT tools and required assets are available."""
    tools_list = [
        "nmap", "gobuster", "nikto", "ffuf", "nuclei", "dalfox",
        "whois", "sqlmap", "msfconsole", "burpsuite", "whatweb",
        "wpscan", "searchsploit", "wafw00f", "sslscan", "hydra", "john"
    ]
    report = ["=== TOOL CHECK REPORT ==="]
    for t in tools_list:
        status = "INSTALLED" if check_tool_exists(t) else "NOT FOUND"
        report.append(f"  - {t:<15}: {status}")

    # Asset checks (wordlists)
    report.append("\n=== ASSET CHECK REPORT ===")
    report.append(f"  Default wordlist ({DEFAULT_WORDLIST}):")
    if check_asset_exists(DEFAULT_WORDLIST):
        report.append(f"    Status: FOUND")
    else:
        report.append(f"    Status: NOT FOUND — gobuster/ffuf will fail with default settings")

    for wl in DEFAULT_WORDLISTS:
        if wl == DEFAULT_WORDLIST:
            continue
        status = "FOUND" if check_asset_exists(wl) else "NOT FOUND"
        report.append(f"  - {wl:<55}: {status}")

    return "\n".join(report)


@mcp.tool()
async def scope_info() -> str:
    """Return details of the current authorized engagement scope."""
    try:
        info = get_scope_info()
        return (
            f"Engagement Name   : {info.get('engagement_name', 'N/A')}\n"
            f"Authorized By     : {info.get('authorized_by', 'N/A')}\n"
            f"Authorized Targets: {info.get('authorized_targets', [])}\n"
            f"Notes             : {info.get('notes', 'None')}"
        )
    except ScopeError as e:
        return f"[!] {e}"


@mcp.tool()
async def add_scope_target(target: str) -> str:
    """Add a new target to the active authorized scope list."""
    try:
        return add_target(target)
    except Exception as e:
        return f"[!] Error: {e}"


@mcp.tool()
async def remove_scope_target(target: str) -> str:
    """Remove a target from the active authorized scope list."""
    try:
        return remove_target(target)
    except Exception as e:
        return f"[!] Error: {e}"


@mcp.tool()
async def generate_report(target: str) -> str:
    """
    Generate a professional structured Markdown pentest report for a target.
    Pulls recent scan outputs from the audit.log to construct the report.
    """
    try:
        recent_logs = get_recent_logs(40)
        target_host = extract_host(target)

        sections = {}
        for entry in recent_logs:
            entry_host = extract_host(entry.get("target", ""))
            if entry_host == target_host:
                tool = entry.get("tool", "unknown")
                summary = entry.get("result_summary", "")
                if summary:
                    sections[tool] = summary

        if not sections:
            return f"[!] No recent scan logs found for target '{target}'. Run scans first."

        return generate_markdown_report(target, sections)
    except Exception as e:
        return f"[!] Error generating report: {e}"


@mcp.tool()
async def install_missing_tools() -> str:
    """
    Guide the user or help install missing VAPT CLI tools and assets
    on a Debian/Kali system. Returns status and instructions.
    """
    tools_list = [
        "nmap", "gobuster", "nikto", "ffuf", "nuclei", "dalfox",
        "whois", "sqlmap", "msfconsole", "burpsuite", "whatweb",
        "wpscan", "searchsploit", "wafw00f", "sslscan", "hydra", "john"
    ]
    missing = [t for t in tools_list if not check_tool_exists(t)]

    # Check for missing wordlists
    missing_wordlists = [wl for wl in DEFAULT_WORDLISTS if not check_asset_exists(wl)]

    if not missing and not missing_wordlists:
        return "[+] All VAPT tools and assets are already available on this system!"

    report = []

    if missing:
        report.extend([
            f"[-] Found {len(missing)} missing tools: {', '.join(missing)}",
            "",
            "Since these are system binaries, you can install them using apt on Kali/Debian:",
            "  sudo apt-get update",
            f"  sudo apt-get install -y {' '.join(missing)}"
        ])

        # Special instruction for tools that might require custom repos
        if "nuclei" in missing or "dalfox" in missing:
            report.append("\nNote: For nuclei and dalfox, if they are not in the standard apt repository:")
            if "nuclei" in missing:
                report.append("  - Nuclei: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
            if "dalfox" in missing:
                report.append("  - Dalfox: go install github.com/hahwul/dalfox/v2@latest")

    if missing_wordlists:
        report.append("\n[-] Missing wordlist assets:")
        for wl in missing_wordlists:
            report.append(f"  - {wl}")
        report.append("\nTo install standard wordlists on Kali/Debian:")
        report.append("  sudo apt-get install -y wordlists seclists")
        if any("rockyou" in wl for wl in missing_wordlists):
            report.append("  sudo gzip -d /usr/share/wordlists/rockyou.txt.gz  # if compressed")

    return "\n".join(report)


if __name__ == "__main__":
    print_banner()
    mcp.run()

