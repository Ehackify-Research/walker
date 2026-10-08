```text
 ██╗  ██╗  ██╗  █████╗  ██╗     ██╗  ██╗███████╗██████╗ 
 ██║  ██║  ██║ ██╔══██╗ ██║     ██║ ██╔╝██╔════╝██╔══██╗
 ██║  ██║  ██║ ███████║ ██║     █████═╝ █████╗  ██████╔╝
 ██║  ██╗  ██║ ██╔══██║ ██║     ██╔═██╗ ██╔══╝  ██╔══██╗
 ╚██████████╔╝ ██║  ██║ ███████╗██║  ██╗███████╗██║  ██║
  ╚═════╝╚═╝   ╚═╝  ╚═╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                                              by Jineesh
         [ VAPT | MODEL CONTEXT PROTOCOL ENGINE ]
```

# 🕵️ Walker Agent — VAPT Recon MCP Server

> An MCP (Model Context Protocol) server that gives any MCP-compatible AI client (Claude Desktop, Claude Code, etc.) safe, auditable access to industry-standard penetration testing and recon tools — with hard scope enforcement and confirm-gated exploitation.

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/protocol-MCP-6f42c1.svg)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](#license)
[![Status](https://img.shields.io/badge/status-active-brightgreen.svg)](#)

---

## ⚠️ Legal & Ethical Use Notice

**This tool is strictly for authorized security assessments.** Only run it against systems you own or have **explicit, written permission** to test. Unauthorized scanning or exploitation of systems is illegal in most jurisdictions. The scope-enforcement system in this project is a safety net, not a substitute for a signed rules-of-engagement (RoE) document.

---

## Table of Contents

- [Why Walker Agent?](#why-walker-agent)
- [Features](#features)
- [Tool Directory](#tool-directory)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Server](#running-the-server)
- [Connecting to an MCP Client](#connecting-to-an-mcp-client) (Claude Desktop, Claude Code, VS Code, Gemini CLI, Cursor/Windsurf, others)
- [Example Usage](#example-usage)
- [Safety Model](#safety-model)
- [Reporting](#reporting)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Why Walker Agent?

Manually juggling `nmap`, `gobuster`, `nuclei`, `sqlmap`, and a dozen other CLI tools during a pentest engagement is slow and error-prone. Walker Agent wraps the most common recon and exploitation tools behind the **Model Context Protocol**, so an AI assistant can:

- Run a full safe recon sweep with a single command (`scan_all`)
- Reason over the output and suggest next steps
- Only touch systems that are **explicitly in scope**
- Require **human confirmation** before anything intrusive runs
- Automatically generate a clean, client-ready Markdown report at the end

It's built for pentesters and red teamers who want an AI copilot in their workflow without giving that copilot unrestricted access to run exploits on arbitrary targets.

---

## Features

| Feature | Description |
|---|---|
| 🎯 **Scope Enforcement** | Every tool call validates the target against `config/scope.json` before executing. No scope file, no scan. |
| 🛡️ **Confirm-Gated Exploitation** | High-risk tools (SQLMap, Metasploit, Burp Suite, Hydra) require an explicit `confirm=True` flag. |
| 🧵 **Robust Async Execution** | Shared subprocess wrappers gracefully handle missing binaries and timeouts instead of crashing the server. |
| ⚡ **Concurrent Scanning** | `scan_all` fans out web scanners (gobuster, nikto, ffuf, nuclei, dalfox, whatweb, sslscan) concurrently across discovered ports for faster recon. |
| 📝 **Audit Trail** | Every action is logged to `config/audit.log` with timestamp, duration, return code, and a result summary. |
| 📄 **One-Command Reporting** | `generate_report` turns your audit log into a structured Markdown pentest report. |
| 🚫 **No Auto-Exploitation** | `scan_all` only ever runs safe, non-intrusive recon — it will never call sqlmap, hydra, metasploit, or burpsuite on its own. |

---

## Tool Directory

| Tool | Category | Gated By | Description |
|---|---|---|---|
| `nmap_scan` | Safe Recon | Scope | Port / service discovery |
| `wafw00f_scan` | Safe Recon | Scope | Web Application Firewall detection |
| `whatweb_scan` | Safe Recon | Scope | Web application technology fingerprinting |
| `sslscan_scan` | Safe Recon | Scope | SSL/TLS certificate & cipher suite verification |
| `gobuster_scan` | Safe Recon | Scope | Web directory discovery |
| `ffuf_scan` | Safe Recon | Scope | General purpose web fuzzer |
| `nikto_scan` | Safe Recon | Scope | Web server misconfiguration scanner |
| `nuclei_scan` | Safe Recon | Scope | Vulnerability scanning using templates |
| `dalfox_scan` | Safe Recon | Scope | Cross-site Scripting (XSS) scanner |
| `wpscan_scan` | Safe Recon | Scope | WordPress scanner (run manually on detection) |
| `whois_lookup` | OSINT | None | WHOIS database queries |
| `searchsploit_query` | Informational | None | Search local Exploit-DB for known CVE exploits |
| `john_crack` | Crack | Local file | Password hash cracking |
| `sqlmap_scan` | Active Exploit | Scope + Confirm | SQL Injection vulnerability testing |
| `hydra_bruteforce` | Active Exploit | Scope + Confirm | Network service credential brute-forcing |
| `metasploit_scan` | Active Exploit | Scope + Confirm | Spawns an `msfconsole` session |
| `burpsuite_scan` | Active Exploit | Scope + Confirm | Starts Burp Suite targeting the target |
| `scan_all` | Orchestrator | Scope | Runs all safe recon tools concurrently and suggests next steps |
| `check_tools` | Utility | None | Reports which CLI binaries are available in PATH |
| `install_missing_tools` | Utility | None | Suggests `apt-get` commands for any missing CLI tools |
| `scope_info` | Utility | None | Shows active engagement authorization details |
| `add_scope_target` | Management | None | Authorizes a new target in scope |
| `remove_scope_target` | Management | None | Revokes a target's authorization |
| `generate_report` | Reporting | None | Generates a structured Markdown pentest report from audit logs |

---

## Project Structure

```
walker-agent/
├── server.py                  # MCP server entrypoint — registers all tools
├── requirements.txt
├── README.md
├── config/
│   ├── scope.py                # Scope validation logic (ScopeError, assert_in_scope, etc.)
│   ├── scope.example.json      # Template — copy to scope.json and edit
│   ├── scope.json               # 🔒 gitignored — your actual authorized targets
│   ├── audit.py                 # Audit logging helpers
│   └── audit.log                 # 🔒 gitignored — generated at runtime
└── tools/
    ├── helpers.py               # Shared subprocess wrappers, tool-existence checks
    ├── analysis.py              # Port parsing, suggestion engine, report generation
    ├── nmap.py
    ├── gobuster.py
    ├── nikto.py
    ├── ffuf.py
    ├── nuclei.py
    ├── dalfox.py
    ├── whatweb.py
    ├── wafw00f.py
    ├── sslscan.py
    ├── wpscan.py
    ├── whois.py
    ├── searchsploit.py
    ├── john.py
    ├── sqlmap.py
    ├── hydra.py
    ├── metasploit.py
    └── burpsuite.py
```

---

## Prerequisites

- **Python 3.10+**
- **pip**
- A Linux environment (Kali or Debian/Ubuntu recommended) with the underlying CLI security tools installed

---

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/<your-username>/walker-agent.git
   cd walker-agent
   ```

2. **(Recommended) Create a virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install the underlying CLI tools**

   On Kali / Debian / Ubuntu:
   ```bash
   sudo apt-get update
   sudo apt-get install -y nmap gobuster nikto ffuf whatweb wafw00f sslscan \
       whois sqlmap hydra john wpscan
   ```

   `nuclei` and `dalfox` aren't always in the standard apt repos — install via Go if missing:
   ```bash
   go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
   go install github.com/hahwul/dalfox/v2@latest
   ```

   > 💡 Tip: once the server is running, just ask your AI client to run `check_tools` — it will tell you exactly what's missing, and `install_missing_tools` will hand you copy-pasteable install commands.

---

## Configuration

Walker Agent **refuses to run any scan** until a valid scope file exists.

1. Copy the example scope file:
   ```bash
   cp config/scope.example.json config/scope.json
   ```

2. Edit `config/scope.json` with your engagement details. You can mix public hostnames, public IPs/CIDR ranges, and **private/internal IP ranges** (for internal network or on-prem engagements) in the same list:
   ```json
   {
     "engagement_name": "Acme Corp Q3 Pentest",
     "authorized_by": "Jane Doe, CISO",
     "authorized_targets": [
       "example.com",
       "app.staging.acme.com",
       "203.0.113.10",
       "192.168.1.0/24",
       "10.0.0.0/8",
       "172.16.0.0/12"
     ],
     "notes": "Written authorization on file, dated 2026-07-01. No DoS testing."
   }
   ```

   > 🏠 **Private IP ranges**: internal/on-prem engagements commonly authorize entire RFC 1918 blocks rather than individual hosts. The three private ranges are:
   > | Range | CIDR |
   > |---|---|
   > | `10.0.0.0` – `10.255.255.255` | `10.0.0.0/8` |
   > | `172.16.0.0` – `172.31.255.255` | `172.16.0.0/12` |
   > | `192.168.0.0` – `192.168.255.255` | `192.168.0.0/16` |
   >
   > Only add a full private range to scope if your RoE genuinely authorizes the whole subnet — prefer the narrowest CIDR that matches your actual authorization (e.g. `192.168.1.0/24` instead of `192.168.0.0/16`) to avoid accidentally green-lighting out-of-scope hosts on the same private network.

3. You can also manage scope live from your AI client using `add_scope_target` / `remove_scope_target` / `scope_info` — no server restart required:
   > "Add 10.0.0.0/8 to scope, we've been authorized to test the whole internal range."

`config/scope.json` and `config/audit.log` are both git-ignored by default so you never accidentally commit engagement-sensitive data.

### 4. Metasploit RPC Configuration (Optional, for Automated Exploitation)

To allow the AI agent to automate exploitation using Metasploit, you must run it in **RPC Mode**. Otherwise, it will fall back to Legacy Mode (which blocks active exploits and only starts an undriven `msfconsole`).

1. **Start the Metasploit RPC daemon (`msfrpcd`)**:
   Choose a **custom, temporary password** of your choice (this is **NOT** your machine/root password; it is simply a temporary password to secure the connection between the Walker Agent and the Metasploit daemon):
   ```bash
   msfrpcd -P MyCustomPassword123 -S -a 127.0.0.1
   ```

2. **Configure the environment variable**:
   Before starting the Walker Agent or your MCP client, export the exact same password into your system environment:
   ```bash
   export MSF_RPC_PASSWORD=MyCustomPassword123
   ```
   *(Optional: You can also customize `MSF_RPC_HOST` [default: 127.0.0.1] and `MSF_RPC_PORT` [default: 55553] if your daemon runs on a non-standard port or machine).*

---

## Running the Server

```bash
python3 server.py
```

The server communicates over stdio using the MCP protocol and is meant to be launched **by an MCP client**, not used standalone in a terminal.

---

## Connecting to an MCP Client

Walker Agent is a standard **stdio** MCP server, so it works with any MCP-compatible AI client (both **Terminal / CLI AI Agents** and **GUI Chat Clients**). The only thing that differs between clients is *where* the config file lives and whether the top-level key is `mcpServers` or `servers`.

> 💡 In every example, replace `/absolute/path/to/walker-agent/server.py` with the real absolute path on your machine (and remember your virtual environment's `python3` if you used one, e.g., `/home/kali/Documents/walker_agent/walker_agent/venv/bin/python3`).

---

### 💻 Terminal AI Agents (CLI)

#### 1. Claude Code (Terminal AI)

Run this one command directly in your terminal:
```bash
claude mcp add walker-agent -- /home/kali/Documents/walker_agent/walker_agent/venv/bin/python3 /home/kali/Documents/walker_agent/walker_agent/server.py
```

Or add it manually to your project's `.mcp.json` / user-level MCP config:
```json
{
  "mcpServers": {
    "walker-agent": {
      "command": "/home/kali/Documents/walker_agent/walker_agent/venv/bin/python3",
      "args": ["/home/kali/Documents/walker_agent/walker_agent/server.py"]
    }
  }
}
```

#### 2. Gemini CLI (Terminal AI)

Add Walker Agent under `mcpServers` in `~/.gemini/settings.json` (global) or `.gemini/settings.json` (per-project):

```json
{
  "mcpServers": {
    "walker-agent": {
      "command": "/home/kali/Documents/walker_agent/walker_agent/venv/bin/python3",
      "args": ["/home/kali/Documents/walker_agent/walker_agent/server.py"]
    }
  }
}
```

Restart Gemini CLI, then run `/mcp list` in the terminal to confirm Walker Agent is connected and `/mcp reload` if tools don't show up right away.

#### 3. Goose / Aider / Other Terminal Agents

Any terminal agent supporting stdio MCP servers can be launched with:
```bash
/home/kali/Documents/walker_agent/walker_agent/venv/bin/python3 /home/kali/Documents/walker_agent/walker_agent/server.py
```

---

### 🖥️ GUI / Editor AI Clients

#### Claude Desktop

Edit `claude_desktop_config.json` (Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "walker-agent": {
      "command": "/home/kali/Documents/walker_agent/walker_agent/venv/bin/python3",
      "args": ["/home/kali/Documents/walker_agent/walker_agent/server.py"]
    }
  }
}
```

Restart Claude Desktop. The tools in the [Tool Directory](#tool-directory) will appear as available tools in chat.

#### VS Code (GitHub Copilot Chat — Agent Mode)

VS Code uses the key **`servers`**, not `mcpServers` — this is the #1 mistake when porting a config from Claude Desktop.

Create `.vscode/mcp.json` in your workspace (or run **MCP: Open User Configuration** from the Command Palette for a global setup):

```json
{
  "servers": {
    "walker-agent": {
      "type": "stdio",
      "command": "/home/kali/Documents/walker_agent/walker_agent/venv/bin/python3",
      "args": ["/home/kali/Documents/walker_agent/walker_agent/server.py"]
    }
  }
}
```

Reload the window (**Developer: Reload Window**), make sure Copilot Chat is in **Agent Mode**, and the tools will show up in the tools picker.

#### Cursor / Windsurf / other `mcpServers`-style clients

These clients follow the same `mcpServers` JSON convention as Claude Desktop — reuse the exact config block shown for Claude Desktop above in the client's respective MCP settings file (e.g. `~/.cursor/mcp.json`).

### Generic / Unsupported Clients

Any MCP host that supports **stdio** transport can run Walker Agent with just:

```
command: python3
args:    ["/absolute/path/to/walker-agent/server.py"]
```

Consult your client's docs for where this belongs — the command and args never change, only the surrounding file format and key names do.

---

## Example Usage

Once connected, you can simply talk to your AI client:

> "Check which VAPT tools I have installed."
→ calls `check_tools`

> "Add example.com to my authorized scope."
→ calls `add_scope_target`

> "Run a full recon sweep against example.com."
→ calls `scan_all`, which chains `nmap` → `wafw00f` → parallel web scanners, and returns a suggestions report

> "Nuclei flagged a potential SQLi endpoint — go ahead and confirm with sqlmap."
→ calls `sqlmap_scan(target=..., confirm=True)`

> "Generate a report for example.com."
→ calls `generate_report`, producing a Markdown pentest report from the audit log

---

## Safety Model

Walker Agent is built around three layers of protection:

1. **Scope Enforcement** — nearly every tool calls `assert_in_scope(target)` before doing anything. If the target isn't in `config/scope.json`, the tool returns an error instead of running.
2. **Confirm-Gating** — `sqlmap_scan`, `hydra_bruteforce`, `metasploit_scan`, and `burpsuite_scan` all require `confirm=True`. Without it, they refuse to execute, forcing an explicit human-in-the-loop decision before anything intrusive happens.
3. **No Auto-Chaining Into Exploits** — `scan_all` is designed to be safe-by-default. It only ever runs recon/fingerprinting tools and never automatically pivots into active exploitation, even if a vulnerability looks obvious in the output.

All tool invocations are recorded in `config/audit.log`, giving you a full timestamped trail of everything that was run, against what, and with what result — useful for both accountability and for building the final client report.

---

## Reporting

`generate_report(target)` pulls the most recent matching entries from `config/audit.log` and assembles them into a clean, structured Markdown pentest report — ready to hand off or convert to PDF/Word for a client deliverable.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| A tool returns `[!] ...` scope error | Add the target with `add_scope_target` or check `config/scope.json` exists |
| A tool returns "not found" / times out | Run `check_tools` to confirm the binary is installed and on PATH |
| `generate_report` says no logs found | Run at least one scan against that exact target first |
| Server won't start | Confirm `requirements.txt` is installed and you're on Python 3.10+ |

---

## Contributing

Contributions are welcome! A few ground rules:

- New "active exploit" tools must be confirm-gated and scope-checked, following the existing pattern in `tools/sqlmap.py` or `tools/hydra.py`.
- New recon tools should be added to `scan_all`'s concurrent battery only if they are non-intrusive.
- Please open an issue before submitting large feature PRs so we can discuss design/scope.

```bash
# Fork, then:
git checkout -b feature/my-new-tool
# make changes
git commit -m "Add my-new-tool"
git push origin feature/my-new-tool
# open a PR
```

---

## Disclaimer

This tool is strictly for **authorized security assessments under active rules of engagement**. Always obtain written permission before executing any scanner or exploit against a target. The authors and contributors accept no liability for misuse of this software.

---

## License

Released under the [MIT License](LICENSE).
