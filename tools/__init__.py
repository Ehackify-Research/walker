from .nmap import run_nmap
from .gobuster import run_gobuster
from .nikto import run_nikto
from .ffuf import run_ffuf
from .nuclei import run_nuclei
from .dalfox import run_dalfox
from .whois import run_whois
from .sqlmap import run_sqlmap
from .metasploit import run_metasploit
from .burpsuite import run_burpsuite
from .john import run_john

# New tools
from .whatweb import run_whatweb
from .wpscan import run_wpscan
from .searchsploit import run_searchsploit
from .wafw00f import run_wafw00f
from .sslscan import run_sslscan
from .hydra import run_hydra

from .analysis import extract_open_ports, build_suggestions_report, build_url, generate_markdown_report

__all__ = [
    "run_nmap",
    "run_gobuster",
    "run_nikto",
    "run_ffuf",
    "run_nuclei",
    "run_dalfox",
    "run_whois",
    "run_sqlmap",
    "run_metasploit",
    "run_burpsuite",
    "run_john",
    "run_whatweb",
    "run_wpscan",
    "run_searchsploit",
    "run_wafw00f",
    "run_sslscan",
    "run_hydra",
    "extract_open_ports",
    "build_suggestions_report",
    "build_url",
    "generate_markdown_report",
]
