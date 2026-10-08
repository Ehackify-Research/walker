"""
Analysis helpers: turn raw nmap output into categorized ports, and turn
categorized ports + service banners into a *suggestions* report.

Important design point: everything in this module produces text for a
human analyst to read. Nothing here calls subprocess, nothing here
invokes sqlmap/metasploit/burpsuite. The output is meant to be the thing
a tester reads before they manually and deliberately decide what to run
next.
"""

import re

HTTPS_PORTS = {443, 8443, 4443, 9443, 3443}
KNOWN_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 4443, 9090, 9443, 3443}
SQL_PORTS = {3306, 5432, 1433, 1521}

# very small reference table of (port/service substring) -> known CVE
# classes worth investigating manually. This is intentionally a
# *pointer to research*, not exploit code or commands.
KNOWN_SERVICE_NOTES = {
    "ftp": "Check for anonymous FTP login and outdated vsftpd/ProFTPd CVEs.",
    "ssh": "Check SSH version against known CVEs (e.g. outdated OpenSSH); review for weak auth/key reuse. Suggested: hydra (SSH).",
    "telnet": "Telnet is unencrypted by design — flag as a finding regardless of version.",
    "smtp": "Check for open relay, VRFY/EXPN user enumeration.",
    "mysql": "Check for default/weak credentials, version-specific CVEs. Suggested: sqlmap/hydra (MySQL).",
    "postgres": "Check for default/weak credentials, version-specific CVEs. Suggested: sqlmap/hydra (Postgres).",
    "microsoft-ds": "SMB — check for EternalBlue-class issues, null sessions, share enumeration.",
    "netbios-ssn": "NetBIOS — check for null sessions and share enumeration.",
    "rdp": "Check RDP version for known CVEs (e.g. BlueKeep-class); verify NLA is enforced.",
    "vnc": "Check for unauthenticated VNC access.",
    "wordpress": "WordPress detected. Suggested: run wpscan against target.",
    "http": "Web server detected. Suggested: run whatweb, wafw00f, and dir scan.",
}


def extract_open_ports(nmap_result: str) -> dict:
    """Parse nmap output into categorized port/service info."""
    web_ports = set()
    sql_ports = set()
    all_ports = set()
    services = {}  # port -> (service, version_string)

    for line in nmap_result.splitlines():
        m = re.match(r"(\d+)/tcp\s+open\s+(\S+)(?:\s+(.*))?", line)
        if m:
            port, service, version = int(m[1]), m[2].lower(), (m[3] or "").strip()
            all_ports.add(port)
            services[port] = (service, version)
            if port in KNOWN_WEB_PORTS or "http" in service:
                web_ports.add(port)
            if port in SQL_PORTS or "sql" in service:
                sql_ports.add(port)

    return {
        "web": sorted(web_ports),
        "sql": sorted(sql_ports),
        "all": sorted(all_ports),
        "services": services,
    }


def build_url(target: str, port: int) -> str:
    scheme = "https" if port in HTTPS_PORTS else "http"
    return f"{scheme}://{target}:{port}"


def build_suggestions_report(target: str, ports: dict) -> str:
    """
    Build a human-readable, informational suggestions report.

    This NEVER returns shell commands meant to be auto-executed by an
    agent loop — it's written as analyst guidance: what was found, what
    class of issue it might indicate, and which tool a human could choose
    to run next (manually, with their own judgment on scope/safety).
    """
    lines = ["\n=== ANALYSIS: POSSIBLE AREAS OF INTEREST ==="]

    if not ports["all"]:
        lines.append("No open ports found — nothing further to suggest.")
        return "\n".join(lines)

    services = ports["services"]

    # service-specific notes
    notable = []
    for port, (service, version) in services.items():
        for key, note in KNOWN_SERVICE_NOTES.items():
            if key in service:
                notable.append(f"  - Port {port}/{service} {version}: {note}")
                break
    if notable:
        lines.append("\n[Service-specific notes]")
        lines.extend(notable)

    if ports["web"]:
        lines.append(f"\n[Web services found on ports {ports['web']}]")
        lines.append(
            "  Suggested manual follow-up (run individually, review each result before proceeding):"
        )
        for p in ports["web"]:
            url = build_url(target, p)
            lines.append(f"  - {url}: technology fingerprinting (whatweb), WAF check (wafw00f), "
                         f"directory enumeration (gobuster/ffuf), vuln scan (nikto), template scan (nuclei), XSS check (dalfox)")
            if p in HTTPS_PORTS:
                lines.append(f"  - {url}: SSL/TLS check (sslscan)")

    if ports["sql"]:
        lines.append(f"\n[Database services found on ports {ports['sql']}]")
        lines.append(
            "  Database ports exposed directly is itself worth flagging as a finding "
            "(should typically not be internet-facing). If web app behind it shows "
            "SQL-error behavior, that's the signal to consider SQLi testing — "
            "as a separate, deliberate, confirmed step, not automatic."
        )

    other = [p for p in ports["all"] if p not in ports["web"] and p not in ports["sql"]]
    if other:
        lines.append(f"\n[Other open ports]: {other}")
        lines.append("  Manual investigation recommended — identify service/version and check for known CVEs.")

    lines.append(
        "\n[Note] This section is informational only. No exploitation tool runs "
        "automatically. Use the confirm-gated exploitation tools manually if, "
        "and only if, your engagement scope and rules of engagement permit it."
    )

    return "\n".join(lines)


def generate_markdown_report(target: str, sections: dict[str, str]) -> str:
    """
    Generate a structured, professional Markdown pentest report for a target
    given the raw outputs from various scanners.
    """
    report = []
    report.append(f"# VAPT Engagement Scan Report: {target}")
    report.append("")
    report.append("## Executive Summary")
    report.append("This report summarizes the automated and manual scanner outputs gathered for the target host. ")
    report.append("All scans were run within the verified engagement scope boundaries.")
    report.append("")
    report.append("---")
    report.append("")

    for sec_name, sec_content in sections.items():
        if sec_content:
            report.append(f"## Section: {sec_name.upper()}")
            report.append("```text")
            # Limit very long outputs to keep the report readable but detailed
            lines = sec_content.splitlines()
            if len(lines) > 200:
                report.append("\n".join(lines[:200]))
                report.append(f"\n... [Truncated {len(lines) - 200} lines of output] ...")
            else:
                report.append(sec_content)
            report.append("```")
            report.append("")

    report.append("---")
    report.append("## Recommendations & Next Steps")
    report.append("1. **Verify Services**: Review service banners and verify identified versions against Exploit-DB (`searchsploit`).")
    report.append("2. **Address Web Findings**: Investigate any endpoints discovered during directory fuzzing/enumeration.")
    report.append("3. **Remediate Weak SSL/TLS**: If weak ciphers or legacy protocol support were identified, update server configuration to use modern TLS suites.")
    report.append("4. **Restricted Actions**: If vulnerabilities such as SQL Injection are suspected, verify authorization details and run confirm-gated tools with explicit operator oversight.")

    return "\n".join(report)
