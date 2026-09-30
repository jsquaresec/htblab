"""The approved-action menu.

The orchestration layer may ONLY choose actions from this table with these
argument templates — never free-form shell. `tier` controls whether human
approval is required. `flag_check` marks actions whose output may contain
an actual flag (we never regex-scan unrelated tool output for flags).
"""
from config import SCAN_DIR
import os
import re


def _scan(job_id, name):
    return f"{SCAN_DIR}/{job_id}_{name}.txt"


def _gobuster_wordlist():
    """Resolve a packaged Kali directory wordlist at runtime."""
    candidates = (
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/dirb/wordlists/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    )
    for path in candidates:
        if os.path.isfile(path):
            return path
    
    # Fallback: create minimal wordlist if packages missing
    fallback = "/tmp/gobuster-common.txt"
    if not os.path.isfile(fallback):
        with open(fallback, 'w') as f:
            f.write("admin\napi\nbackup\nconfig\ndev\nlogin\nrobots.txt\n")
    return fallback


ACTIONS = {
    "nmap_full": {
        "tier": "enum", "desc": "Full TCP port scan",
        "build": lambda ip, ctx: ["nmap", "-p-", "--min-rate", "2000",
                                  "-oN", _scan(ctx["job_id"], "full"), ip],
    },
    "nmap_scripts": {
        "tier": "enum", "desc": "Service/version + default scripts on open ports",
        "build": lambda ip, ctx: ["nmap", "-sV", "-sC", "-p", ctx["ports"],
                                  "-oN", _scan(ctx["job_id"], "scripts"), ip],
    },
    "gobuster": {
    "tier": "enum", "desc": "HTTP directory brute-force",
    "build": lambda ip, ctx: ["gobuster", "dir", "-u", f"http://{ip}",
                               "-w", _gobuster_wordlist(),
                               "-o", _scan(ctx["job_id"], "gobuster")],
},
    },
    "nikto": {
        "tier": "enum", "desc": "Web server vulnerability scan",
        "build": lambda ip, ctx: ["nikto", "-h", ip,
                                  "-output", _scan(ctx["job_id"], "nikto")],
    },
    "enum4linux": {
        "tier": "enum", "desc": "SMB/RPC enumeration",
        "build": lambda ip, ctx: ["enum4linux-ng", "-A", ip,
                                  "-oA", _scan(ctx["job_id"], "enum4linux")],
    },
    "ftp_anon": {
        "tier": "enum", "desc": "Check FTP anonymous login",
        "build": lambda ip, ctx: ["nmap", "--script", "ftp-anon,ftp-syst",
                                  "-p", "21", ip],
    },
    "ssh_auth_methods": {
        "tier": "enum", "desc": "Check SSH auth methods",
        "build": lambda ip, ctx: ["nmap", "--script", "ssh-auth-methods",
                                  "-p", "22", ip],
    },
    "ssh_grab_flags": {
        "tier": "exploit", "flag_check": True,
        "desc": "SSH with supplied creds to read user.txt / root.txt",
        "needs_creds": True,
        "build": lambda ip, ctx: [
            "sshpass", "-p", ctx["password"], "ssh",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            f"{ctx['username']}@{ip}",
            "cat /home/*/user.txt ~/user.txt 2>/dev/null; "
            "echo ---ROOT---; sudo -n cat /root/root.txt 2>/dev/null"],
    },
}


def parse_open_ports(nmap_text):
    return sorted({int(m.group(1)) for m in
                   re.finditer(r"^(\d+)/tcp\s+open", nmap_text, re.M)})


def plan(open_ports, has_creds):
    """Rule-based orchestration: react to what enumeration found."""
    p = set(open_ports)
    steps = ["nmap_scripts"]
    if p & {80, 443, 8080, 8000}:
        steps += ["gobuster", "nikto"]
    if p & {445, 139}:
        steps.append("enum4linux")
    if 21 in p:
        steps.append("ftp_anon")
    if 22 in p:
        steps.append("ssh_auth_methods")
    if has_creds and 22 in p:
        steps.append("ssh_grab_flags")
    return steps


FLAG_RE = re.compile(r"HTB\{[^}\r\n]+\}|(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])")


def detect_flags(text):
    """Return real flags only — matches against actual retrieved output."""
    return list(dict.fromkeys(FLAG_RE.findall(text)))
