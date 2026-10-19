import argparse
import asyncio
import csv
import ipaddress
import json
import os
import platform
import random
import re
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "Submission",
    636: "LDAPS", 902: "VMware Auth", 912: "VMware Auth", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9090: "WebConsole",
    11211: "Memcached", 27017: "MongoDB",
}

RISK_TABLE = {
    21: ("HIGH", "FTP transmits credentials in plaintext"),
    23: ("CRITICAL", "Telnet is unencrypted; use SSH instead"),
    53: ("MEDIUM", "DNS can be abused for amplification if open"),
    111: ("MEDIUM", "RPCbind exposes service map"),
    135: ("HIGH", "MSRPC often targeted by exploits"),
    139: ("HIGH", "NetBIOS legacy Windows sharing"),
    389: ("MEDIUM", "LDAP may leak directory info if unauthenticated"),
    445: ("HIGH", "SMB exposed; ransomware/worm vector"),
    902: ("MEDIUM", "VMware auth daemon; bind to localhost if not needed"),
    912: ("MEDIUM", "VMware auth daemon; bind to localhost if not needed"),
    1433: ("MEDIUM", "Database port should not be publicly exposed"),
    1521: ("MEDIUM", "Database port should not be publicly exposed"),
    3306: ("MEDIUM", "MySQL should be bound internally"),
    3389: ("HIGH", "RDP exposed; brute-force/ransomware vector"),
    5432: ("MEDIUM", "PostgreSQL should be bound internally"),
    5900: ("HIGH", "VNC often weakly authenticated/unencrypted"),
    6379: ("HIGH", "Redis is frequently deployed without auth"),
    11211: ("HIGH", "Memcached amplification abuse risk"),
    27017: ("HIGH", "MongoDB often exposed without auth"),
}

HTTP_PORTS = {80, 591, 8000, 8008, 8080, 8081, 8443, 9090}
TLS_PORTS = {443, 465, 563, 636, 993, 995, 8443}
DEFAULT_PORTS = sorted(set(KNOWN_SERVICES))
TOP_PORTS = [22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389,
             3306, 5432, 5900, 6379, 8080, 8443, 27017, 9090]
ALL_TCP_PORTS = list(range(1, 65536))

UDP_PORTS = {
    53: "DNS", 67: "DHCP", 69: "TFTP", 123: "NTP", 137: "NetBIOS-NS",
    161: "SNMP", 500: "IKE", 514: "Syslog", 1900: "SSDP",
}

def _dns_probe():
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"

UDP_PROBES = {
    53: _dns_probe(),
    123: b"\x1b" + b"\x00" * 47,
    161: bytes.fromhex("302902010104067075626c6963a01c020400000001020100020100300e300c06082b060102010101000500"),
}

UDP_RISK = {
    53: ("MEDIUM", "Open DNS resolver; check amplification/zone exposure"),
    69: ("HIGH", "TFTP has no authentication"),
    123: ("MEDIUM", "NTP can be abused for amplification"),
    137: ("HIGH", "NetBIOS name service leaks host info"),
    161: ("HIGH", "SNMP with default communities exposes device info"),
    1900: ("MEDIUM", "SSDP can be abused for amplification"),
}

MITRE_MAP = {
    21: "T1021 Remote Services", 22: "T1021.004 SSH", 23: "T1021 Remote Services",
    25: "T1566 Phishing exfil path", 53: "T1071.004 DNS C2 channel",
    80: "T1190 Exploit public-facing app", 111: "T1046 Network discovery",
    135: "T1021.006 WinRM/RPC", 139: "T1021.002 SMB", 389: "T1087 Account discovery",
    443: "T1190 Exploit public-facing app", 445: "T1021.002 SMB/Windows Admin Shares",
    1433: "T1190/T1210 Exploit remote service", 1521: "T1190/T1210 Exploit remote service",
    3306: "T1190/T1210 Exploit remote service", 3389: "T1021.001 RDP",
    5432: "T1190/T1210 Exploit remote service", 5900: "T1021.005 VNC",
    6379: "T1210 Exploitation of remote services", 8080: "T1190 Exploit public-facing app",
    11211: "T1498 Network DoS (amplification)", 27017: "T1210 Exploitation of remote services",
}

COMPLIANCE_MAP = {
    21: ["PCI-DSS 2.2.2", "CIS 4.1"], 23: ["PCI-DSS 2.2.2", "CIS 4.5"],
    53: ["CIS 4.1"], 80: ["PCI-DSS 6.5"], 111: ["CIS 4.1"],
    135: ["CIS 18.8"], 139: ["PCI-DSS 1.3", "CIS 18.4"], 389: ["CIS 4.1"],
    443: ["PCI-DSS 6.5"], 445: ["PCI-DSS 1.3", "CIS 18.4"],
    1433: ["PCI-DSS 1.3"], 1521: ["PCI-DSS 1.3"], 3306: ["PCI-DSS 1.3"],
    3389: ["CIS 18.9", "PCI-DSS 1.3"], 5432: ["PCI-DSS 1.3"],
    5900: ["PCI-DSS 1.3", "CIS 4.1"], 6379: ["PCI-DSS 1.3"],
    11211: ["CIS 4.1"], 27017: ["PCI-DSS 1.3"],
}

REMEDIATION_MAP = {
    21: ["sudo ufw deny 21/tcp", "Migrate file transfers to SFTP/SCP over SSH"],
    23: ["sudo systemctl disable --now telnet.socket 2>/dev/null || true", "sudo ufw deny 23/tcp", "Replace Telnet with SSH (encrypted)"],
    25: ["Restrict SMTP to mail relays only; enforce TLS (587 for submission)"],
    53: ["Restrict recursion; apply response-rate limiting (RRL)"],
    111: ["sudo ufw deny 111", "Disable rpcbind if NFS is not required"],
    135: ["sudo ufw deny 135/tcp", "Block MSRPC at perimeter firewall"],
    139: ["sudo ufw deny 139/tcp", "Disable NetBIOS; use SMB over 445 with signing"],
    389: ["Require LDAPS (636) or StartTLS; restrict source IPs"],
    445: ["sudo ufw deny 445/tcp", "Never expose SMB to untrusted networks"],
    902: ["Bind VMware auth daemon to localhost; disable if Workstation sharing unused"],
    912: ["Bind VMware auth daemon to localhost; disable if Workstation sharing unused"],
    1433: ["Bind MSSQL to internal interfaces; require VPN for admin access"],
    1521: ["Bind Oracle to internal interfaces; require VPN for admin access"],
    3306: ["bind-address=127.0.0.1 in my.cnf", "sudo ufw deny 3306/tcp"],
    3389: ["Put RDP behind VPN/Gateway", "sudo ufw deny 3389/tcp", "Enable NLA + account lockout policies"],
    5432: ["listen_addresses='localhost' in postgresql.conf", "sudo ufw deny 5432/tcp"],
    5900: ["Tunnel VNC over SSH", "sudo ufw deny 5900/tcp"],
    6379: ["Set 'requirepass' + 'bind 127.0.0.1' in redis.conf", "sudo ufw deny 6379/tcp"],
    11211: ["Run memcached with -l 127.0.0.1 and enable SASL auth", "sudo ufw deny 11211"],
    27017: ["Enable auth, bindIp: 127.0.0.1 in mongod.conf", "sudo ufw deny 27017/tcp"],
}

CVE_DB = {
    "openssh": [
        {"min": "8.5", "max": "9.7", "id": "CVE-2024-6387", "severity": "HIGH", "summary": "regreSSHion: signal-handler race condition RCE"},
        {"min": "0.0", "max": "7.6", "id": "CVE-2018-15473", "severity": "MEDIUM", "summary": "Username enumeration via malformed auth packets"},
    ],
    "apache": [
        {"min": "2.4.49", "max": "2.4.49", "id": "CVE-2021-41773", "severity": "CRITICAL", "summary": "Path traversal + RCE in Apache httpd 2.4.49"},
        {"min": "2.4.50", "max": "2.4.50", "id": "CVE-2021-42013", "severity": "CRITICAL", "summary": "Bypass of CVE-2021-41773 fix in 2.4.50"},
    ],
    "vsftpd": [
        {"min": "2.3.4", "max": "2.3.4", "id": "VSFTPD-BACKDOOR-2011", "severity": "CRITICAL", "summary": "vsftpd 2.3.4 was released with a backdoor (compromised source)"},
    ],
    "proftpd": [
        {"min": "1.3.0", "max": "1.3.5", "id": "CVE-2015-3306", "severity": "HIGH", "summary": "mod_copy allows unauthenticated arbitrary file copy"},
    ],
}

VERSION_PATTERNS = [
    (r"OpenSSH[_ ]v?(\d+\.\d+(?:\.\d+)?(?:p\d+)?)", "openssh"),
    (r"Apache(?:/| httpd/| )(\d+\.\d+\.\d+)", "apache"),
    (r"nginx/(\d+\.\d+(?:\.\d+)?)", "nginx"),
    (r"vsftpd[ /v]*([\d.]+)", "vsftpd"),
    (r"ProFTPD[ v/]*([\d.]+)", "proftpd"),
]

def _vtuple(v):
    nums = re.findall(r"\d+", v)
    return tuple(int(n) for n in nums) or (0,)

def _vle(a, b):
    ta, tb = _vtuple(a), _vtuple(b)
    n = max(len(ta), len(tb))
    return ta + (0,) * (n - len(ta)) <= tb + (0,) * (n - len(tb))

def identify_software(banner):
    for pat, name in VERSION_PATTERNS:
        m = re.search(pat, banner, re.I)
        if m:
            return name, m.group(1)
    return None, None

def match_cves(banner):
    sw, ver = identify_software(banner)
    if not sw or not ver:
        return []
    out = []
    for e in CVE_DB.get(sw, []):
        if _vle(e["min"], ver) and _vle(ver, e["max"]):
            out.append({"id": e["id"], "severity": e["severity"], "summary": e["summary"], "software": sw, "version": ver})
    return out

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
MAX_SWEEP_HOSTS = 1024
SEV_COLOR = {"CRITICAL": "\033[1;31m", "HIGH": "\033[0;31m", "MEDIUM": "\033[0;33m", "LOW": "\033[0;32m", "INFO": "\033[0;36m"}
GRADE_COLOR = {"A": "\033[1;32m", "B": "\033[0;32m", "C": "\033[1;33m", "D": "\033[0;33m", "F": "\033[1;31m"}
RESET = "\033[0m"
ANSI_RE = re.compile(r"\033\[[0-9;]*m")

SCAN_LEVELS = {
    1: {"name": "QUICK", "tcp_default": TOP_PORTS, "udp_default": [], "grab_banners": False, "max_workers": None, "jitter": (0.0, 0.0), "syn": False, "tls": False, "desc": "Top ~20 TCP ports, fastest"},
    2: {"name": "STANDARD", "tcp_default": DEFAULT_PORTS, "udp_default": [], "grab_banners": True, "max_workers": None, "jitter": (0.0, 0.0), "syn": False, "tls": True, "desc": "Common ports + banners + TLS checks"},
    3: {"name": "DEEP", "tcp_default": "full", "udp_default": "common", "grab_banners": True, "max_workers": None, "jitter": (0.0, 0.0), "syn": False, "tls": True, "desc": "Full 1-1024 + common UDP + banners + TLS"},
    4: {"name": "STEALTH", "tcp_default": "full", "udp_default": [], "grab_banners": False, "max_workers": 4, "jitter": (0.05, 0.5), "syn": True, "tls": False, "desc": "SYN if root, else slow quiet connect scan"},
    5: {"name": "FULL", "tcp_default": "all", "udp_default": [], "grab_banners": True, "max_workers": None, "jitter": (0.0, 0.0), "syn": False, "tls": True, "desc": "ALL 65,535 TCP ports + banners + TLS"},
}

def print_levels():
    print("\n  ╭─ Scan Levels ───────────────────────────────────────────────╮")
    for n in sorted(SCAN_LEVELS):
        print(f"  │  [{n}] {SCAN_LEVELS[n]['name']:<9} ─ {SCAN_LEVELS[n]['desc']:<42} │")
    print("  ╰─────────────────────────────────────────────────────────────╯")

def prompt_level(default=2):
    if not sys.stdin.isatty():
        return default
    print_levels()
    while True:
        try:
            raw = input(f"\n  ❯ Select scan level [1-{max(SCAN_LEVELS)}, default {default}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return default
        if not raw:
            return default
        try:
            n = int(raw)
            if n in SCAN_LEVELS:
                return n
        except ValueError:
            pass
        print(f"    ↳ Please enter a valid choice between 1 and {max(SCAN_LEVELS)}")

def prompt_workers(default, max_threads):
    if not sys.stdin.isatty():
        return default
    while True:
        try:
            raw = input(f"  ❯ How many worker threads? [1-{max_threads}, default {default}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return default
        if not raw:
            return default
        try:
            n = int(raw)
            if 1 <= n <= max_threads:
                return n
            print(f"    ↳ Range allowed: 1-{max_threads}")
        except ValueError:
            print("    ↳ Integer required")

def system_info():
    info = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count() or 1,
        "max_open_files_soft": None,
        "max_open_files_hard": None
    }
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        info["max_open_files_soft"], info["max_open_files_hard"] = soft, hard
    except Exception:
        pass
    soft = info["max_open_files_soft"]
    info["max_worker_threads"] = max(1, min(4096, soft // 2)) if soft else 512
    info["default_worker_threads"] = max(16, min(200, info["max_worker_threads"]))
    return info

def print_system_info(info):
    print("  ╭─ Environment Info ──────────────────────────────────────────╮")
    print(f"  │  Platform       : {info['platform'][:41]:<41} │")
    print(f"  │  Logical CPUs   : {info['cpu_count']:<41} │")
    if info["max_open_files_soft"]:
        print(f"  │  FD Limits      : soft={info['max_open_files_soft']}, hard={info['max_open_files_hard']:<21} │")
    print(f"  │  Max Threads    : {info['max_worker_threads']:<41} │")
    print("  ╰─────────────────────────────────────────────────────────────╯\n")

def enable_windows_console():
    if sys.platform != "win32":
        return
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        k32.SetConsoleMode(k32.GetStdHandle(-11), 7)
    except Exception:
        pass

def print_banner(info):
    print("\033[1;36m")
    print("  ┌─────────────────────────────────────────────────────────────┐")
    print("  │             🛡️   P O R T   A U D I T O R   v4.2             │")
    print("  │       continuous network exposure auditing · stdlib-only    │")
    print("  │                     made by arhaam-khan1                    │")
    print("  └─────────────────────────────────────────────────────────────┘")
    print("\033[0m")
    print(f"  Python {info['python']} · {info['platform'][:35]} · max {info['max_worker_threads']} threads\n")

class Progress:
    def __init__(self, total, width=32):
        self.total = max(total, 1)
        self.done = 0
        self.width = width
        self.lock = threading.Lock()
        self.start = time.time()

    def bump(self):
        with self.lock:
            self.done += 1
            done = self.done
        if sys.stdout.isatty():
            frac = done / self.total
            filled = int(self.width * frac)
            bar = "━" * filled + "─" * (self.width - filled)
            rate = done / max(time.time() - self.start, 0.001)
            sys.stdout.write(f"\r  ╟─[{bar}]─╢ {done}/{self.total} probes ({rate:,.0f}/s) ")
            if done >= self.total:
                sys.stdout.write("\n")
            sys.stdout.flush()

DASH_LOCK = threading.Lock()
DASH_STATE = {
    "updated": None, "level": "", "watch": False,
    "hosts": {}, "alerts": [], "benchmark": {}, "score_history": {}
}

def update_dash_state(report):
    slim = {}
    for host, hd in report["hosts"].items():
        slim[host] = {
            "score": hd.get("score"), "grade": hd.get("grade"),
            "open_count": hd["open_count"], "tls": hd.get("tls", []),
            "findings": [{
                k: f.get(k) for k in
                ("protocol", "port", "state", "service", "risk", "unexpected", "mitre", "banner", "cves")
            } for f in hd["findings"]],
        }
    with DASH_LOCK:
        DASH_STATE.update({
            "updated": report["scanned_at"], "level": report["level"],
            "hosts": slim, "benchmark": report.get("benchmark", {})
        })
        for host, hd in report["hosts"].items():
            if hd.get("score") is not None:
                DASH_STATE["score_history"].setdefault(host, []).append(hd["score"])
        for h in DASH_STATE["score_history"]:
            del DASH_STATE["score_history"][h][:-60]

DASH_HTML = """<!doctype html><html><head><meta charset="utf-8">
<title>Port Auditor — Live Dashboard</title><style>
body{background:#0f1419;color:#e6e6e6;font-family:'Segoe UI',Arial,sans-serif;margin:0}
header{background:#151d26;padding:14px 24px;display:flex;align-items:center;gap:16px;border-bottom:2px solid #253341}
h1{font-size:18px;margin:0;color:#7ec8ff}
.meta{color:#8899a6;font-size:12px}
button{background:#1d9bf0;border:none;color:#fff;padding:8px 16px;border-radius:20px;font-weight:600;cursor:pointer}
button:hover{background:#1a8cd8}
main{padding:20px 24px}
.cards{display:flex;flex-wrap:wrap;gap:16px;margin-bottom:20px}
.card{background:#151d26;border:1px solid #253341;border-radius:10px;padding:16px 20px;min-width:220px}
table{border-collapse:collapse;width:100%;background:#151d26;border-radius:8px;overflow:hidden}
th,td{padding:8px 12px;text-align:left;font-size:12px;border-bottom:1px solid #22303c}
th{background:#1c2732;color:#8899a6;text-transform:uppercase;font-size:11px}
.badge{color:#fff;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700}
.alerts{margin-top:20px}
.alert{padding:8px 12px;border-radius:6px;margin-bottom:6px;font-size:12px;background:#151d26;border-left:4px solid #8899a6}
h2{font-size:14px;color:#8899a6;text-transform:uppercase;margin:24px 0 10px}
</style></head><body>
<header><h1>🛡️ Port Auditor</h1><span class="meta" id="meta">loading…</span>
<button onclick="fetch('/api/scan',{method:'POST'})">⟳ Scan Now</button></header>
<main><div class="cards" id="cards"></div>
<h2>Score trend</h2><div class="card" id="trend"></div>
<h2>Open ports &amp; findings</h2>
<table><thead><tr><th>Host</th><th>Port</th><th>Proto</th><th>State</th><th>Service</th>
<th>Risk</th><th>CVEs</th><th>MITRE</th><th>Banner</th></tr></thead><tbody id="rows"></tbody></table>
<h2>TLS certificates</h2>
<table><thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Subject</th>
<th>Days left</th><th>Issues</th></tr></thead><tbody id="tls"></tbody></table>
<div class="alerts"><h2>Alert feed</h2><div id="alerts"></div></div></main>
<script>
const COLORS={CRITICAL:'#7a0c0c',HIGH:'#c0392b',MEDIUM:'#e67e22',LOW:'#27ae60',INFO:'#7f8c8d'};
function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;')}
function donut(score,grade){
 const C=2*Math.PI*26;
 const color={A:'#2ecc71',B:'#27ae60',C:'#f1c40f',D:'#e67e22',F:'#e74c3c'}[grade]||'#8899a6';
 return `<svg width="76" height="76"><circle cx="38" cy="38" r="26" fill="none" stroke="#22303c" stroke-width="8"/>`+
 `<circle cx="38" cy="38" r="26" fill="none" stroke="${color}" stroke-width="8" stroke-dasharray="${C*score/100} ${C}" stroke-linecap="round" transform="rotate(-90 38 38)"/>`+
 `<text x="38" y="45" text-anchor="middle" fill="${color}" font-size="22" font-weight="bold">${grade}</text></svg>`;}
function render(d){
 document.getElementById('meta').textContent=
  'Updated: '+(d.updated||'never')+' | Level: '+(d.level||'-')+(d.watch?' | WATCH':'');
 const cards=document.getElementById('cards'); cards.innerHTML='';
 for(const [h,v] of Object.entries(d.hosts||{})){
  cards.innerHTML+=`<div class="card" style="display:flex;gap:14px;align-items:center">
   ${donut(v.score??0,v.grade||'?')}
   <div><h3>${esc(h)}</h3><div class="meta">Score: ${v.score??'-'}/100<br>
   Open ports: ${v.open_count}</div></div></div>`;}
 const tr=document.getElementById('trend'); let svg='<svg width="100%" height="90">';
 for(const [h,vals] of Object.entries(d.score_history||{})){
  const v=vals.slice(-20); const step=v.length>1?700/(v.length-1):0;
  const pts=v.map((s,i)=>`${20+i*step},${80-(s/100*70)}`).join(' ');
  if(v.length>1) svg+=`<polyline points="${pts}" fill="none" stroke="#1d9bf0" stroke-width="2"/>`;
  svg+=`<text x="${Math.min(740,20+(v.length-1)*step)+8}" y="${80-(v[v.length-1]/100*70)+4}" fill="#8899a6" font-size="10">${esc(h)}</text>`;}
 tr.innerHTML=svg+'</svg>';
 const rows=document.getElementById('rows'); rows.innerHTML='';
 for(const [h,v] of Object.entries(d.hosts||{}))
  for(const f of v.findings){
   const cves=(f.cves||[]).map(c=>c.id).join(', ');
   rows.innerHTML+=`<tr><td>${esc(h)}</td><td>${f.port}</td><td>${f.protocol}</td>
    <td>${f.state}</td><td>${esc(f.service)}</td>
    <td><span class="badge" style="background:${COLORS[f.risk]||'#555'}">${f.risk}
    ${f.unexpected?' ⚠':''}</span></td><td>${esc(cves)}</td><td>${esc(f.mitre||'')}</td>
    <td>${esc((f.banner||'').slice(0,50))}</td></tr>`;}
 const tls=document.getElementById('tls'); tls.innerHTML='';
 for(const [h,v] of Object.entries(d.hosts||{}))
  for(const t of v.tls||[])
   tls.innerHTML+=`<tr><td>${esc(h)}</td><td>${t.port}</td><td>${esc(t.protocol)}</td>
    <td>${esc(t.subject)}</td><td>${t.days_left??'-'}</td>
    <td>${esc((t.issues||[]).join('; '))}</td></tr>`;
 const al=document.getElementById('alerts'); al.innerHTML='';
 for(const a of (d.alerts||[]).slice(-30).reverse())
  al.innerHTML+=`<div class="alert" style="border-color:${COLORS[a.severity]||'#889'}">
   <b>[${a.severity}]</b> ${esc(a.subject)}: ${esc(a.message)} <span class="meta">${a.ts}</span></div>`;
}
function tick(){fetch('/api/state').then(r=>r.json()).then(render).catch(()=>{});}
tick(); setInterval(tick,2500);
</script></body></html>"""

class DashHandler(BaseHTTPRequestHandler):
    trigger = None

    def _send(self, code, body, ctype):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/api/state":
            with DASH_LOCK:
                self._send(200, json.dumps(DASH_STATE), "application/json")
        else:
            self._send(200, DASH_HTML, "text/html; charset=utf-8")

    def do_POST(self):
        if self.path == "/api/scan" and self.trigger is not None:
            self.trigger.set()
            self._send(200, '{"ok":true}', "application/json")
        else:
            self._send(404, '{"error":"not found"}', "application/json")

    def log_message(self, *args):
        pass

def start_dashboard(port, trigger):
    DashHandler.trigger = trigger
    httpd = ThreadingHTTPServer(("127.0.0.1", port), DashHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd

def _post_webhook(webhook, body):
    try:
        req = urllib.request.Request(
            webhook,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
    except Exception:
        pass

class Notifier:
    def __init__(self, webhook=None, notify_file=None):
        self.webhook = webhook
        self.notify_file = notify_file

    def send(self, subject, message, severity="INFO", data=None, console_only=False):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [{severity}] {subject}: {message}"
        print(f"{SEV_COLOR.get(severity, '')}{line}{RESET}")
        if severity == "CRITICAL":
            try:
                import winsound
                winsound.Beep(880, 120)
                winsound.Beep(520, 250)
            except Exception:
                pass
        if self.notify_file:
            try:
                with open(self.notify_file, "a") as fh:
                    fh.write(line + "\n")
            except OSError:
                pass
        with DASH_LOCK:
            DASH_STATE["alerts"].append({"ts": ts, "severity": severity, "subject": subject, "message": message})
            del DASH_STATE["alerts"][:-100]
        if self.webhook and not console_only:
            if "hooks.slack.com" in self.webhook:
                body = {"text": f"[{severity}] {subject}\n{message}"}
            else:
                body = {"severity": severity, "subject": subject, "message": message, "timestamp": ts}
                if data:
                    body["data"] = data
            threading.Thread(target=_post_webhook, args=(self.webhook, body), daemon=True).start()

def syn_available():
    if os.name != "posix":
        return False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.close()
        return True
    except OSError:
        return False

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()

class SYNScanner:
    def __init__(self, timeout=1.5):
        self.timeout = timeout
        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.sport = random.randint(40000, 60000)
        self.local_ip = get_local_ip()
        self.pending = {}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        threading.Thread(target=self._recv_loop, daemon=True).start()

    @staticmethod
    def _checksum(data):
        if len(data) % 2:
            data += b"\x00"
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return (~s) & 0xFFFF

    def _build(self, src_ip, dst_ip, dst_port, flags, seq=0, ack=0):
        hdr = struct.pack("!HHIIBBHHH", self.sport, dst_port, seq, ack, (5 << 4), flags, 1024, 0, 0)
        pseudo = struct.pack("!4s4sBBH", socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, 6, len(hdr))
        csum = self._checksum(pseudo + hdr)
        return hdr[:16] + struct.pack("!H", csum) + hdr[18:]

    def _recv_loop(self):
        while not self.stop_event.is_set():
            try:
                data, addr = self.recv_sock.recvfrom(65535)
            except OSError:
                break
            if len(data) < 40 or data[9] != 6:
                continue
            ihl = (data[0] & 0x0F) * 4
            tcp = data[ihl:]
            if len(tcp) < 20:
                continue
            sport, dport = struct.unpack("!HH", tcp[:4])
            flags = tcp[13]
            if dport != self.sport:
                continue
            with self.lock:
                item = self.pending.get((addr[0], sport))
            if not item:
                continue
            if flags & 0x04:
                item["result"] = "closed"
                item["event"].set()
            elif flags & 0x12 == 0x12:
                item["result"] = "open"
                item["event"].set()
                src = "127.0.0.1" if addr[0].startswith("127.") else self.local_ip
                try:
                    self.send_sock.sendto(
                        self._build(src, addr[0], sport, 0x04, seq=struct.unpack("!I", tcp[8:12])[0]),
                        (addr[0], sport)
                    )
                except OSError:
                    pass

    def scan(self, host, port):
        return self.scan_many(host, [port]).get(port, "filtered")

    def scan_many(self, host, ports, timeout=None):
        timeout = timeout or self.timeout
        ip = socket.gethostbyname(host)
        src = "127.0.0.1" if ip.startswith("127.") else self.local_ip
        items = {}
        with self.lock:
            for p in ports:
                items[p] = {"event": threading.Event(), "result": "filtered"}
                self.pending[(ip, p)] = items[p]
        try:
            for p in ports:
                pkt = self._build(src, ip, p, 0x02, seq=random.randint(1000, 0x7FFFFFFF))
                self.send_sock.sendto(pkt, (ip, p))
            deadline = time.time() + timeout
            while time.time() < deadline:
                if all(i["event"].is_set() for i in items.values()):
                    break
                time.sleep(0.05)
        finally:
            with self.lock:
                for p in ports:
                    self.pending.pop((ip, p), None)
        return {p: items[p]["result"] for p in ports}

    def close(self):
        self.stop_event.set()
        for s in (self.send_sock, self.recv_sock):
            try:
                s.close()
            except OSError:
                pass

def grab_banner(sock, port):
    try:
        sock.settimeout(1.0)
        if port in HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: audit.local\r\n\r\n")
        data = sock.recv(256)
        return data.decode("utf-8", "replace").strip().replace("\r", "")[:160]
    except (socket.timeout, OSError):
        return ""

def _base_finding(host, proto, port, service, state):
    return {
        "host": host, "protocol": proto, "port": port, "state": state,
        "service": service, "banner": "", "software": "", "version": "",
        "cves": [], "risk": "INFO", "risk_reason": "", "unexpected": False,
        "mitre": "", "compliance": [], "remediation": []
    }

def _enrich_open_finding(f):
    if f["state"] == "open":
        f["risk"], f["risk_reason"] = RISK_TABLE.get(f["port"], ("LOW", "Open service; verify it is required"))
        if f["banner"]:
            sw, ver = identify_software(f["banner"])
            if sw:
                f["software"], f["version"] = sw, ver
            f["cves"] = match_cves(f["banner"])
    return f

def scan_tcp_port(host, port, timeout, grab_banners=True, jitter=(0.0, 0.0)):
    if jitter != (0.0, 0.0):
        time.sleep(random.uniform(*jitter))
    f = _base_finding(host, "tcp", port, KNOWN_SERVICES.get(port, "unknown"), "closed")
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            f["state"] = "open"
            if grab_banners:
                f["banner"] = grab_banner(s, port)
    except (socket.timeout, OSError):
        pass
    return _enrich_open_finding(f)

def _syn_finding(host, port, state):
    f = _base_finding(host, "tcp", port, KNOWN_SERVICES.get(port, "unknown"), state)
    if state == "open":
        _enrich_open_finding(f)
    return f

def scan_udp_port(host, port, timeout):
    f = _base_finding(host, "udp", port, UDP_PORTS.get(port, "unknown"), "open|filtered")
    probe = UDP_PROBES.get(port, b"\x00")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(probe, (host, port))
            try:
                data, _ = s.recvfrom(512)
                f["state"] = "open"
                f["banner"] = data.decode("utf-8", "replace").strip()[:160]
            except socket.timeout:
                pass
            except ConnectionRefusedError:
                f["state"] = "closed"
    except ConnectionRefusedError:
        f["state"] = "closed"
    except OSError:
        pass
    if f["state"] == "open":
        f["risk"], f["risk_reason"] = UDP_RISK.get(port, ("LOW", "Open UDP service; verify it is required"))
    return f

def _tcp_probe_async(host, port, timeout, grab_banners, jitter, progress):
    async def run():
        if jitter != (0.0, 0.0):
            await asyncio.sleep(random.uniform(*jitter))
        f = _base_finding(host, "tcp", port, KNOWN_SERVICES.get(port, "unknown"), "closed")
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            f["state"] = "open"
            if grab_banners:
                try:
                    if port in HTTP_PORTS:
                        writer.write(b"HEAD / HTTP/1.0\r\nHost: audit.local\r\n\r\n")
                        await writer.drain()
                    data = await asyncio.wait_for(reader.read(256), timeout=1.0)
                    f["banner"] = data.decode("utf-8", "replace").strip().replace("\r", "")[:160]
                except Exception:
                    pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            pass
        finally:
            if progress:
                progress.bump()
        if f["state"] == "open":
            _enrich_open_finding(f)
        return f
    return run()

def _run_tcp_async(tcp_tasks, workers, timeout, grab_banners, jitter, progress):
    async def runner():
        concurrency = min(512 if os.name == "nt" else 1024, max(64, workers * 4))
        sem = asyncio.Semaphore(concurrency)

        async def guarded(h, p):
            async with sem:
                return await _tcp_probe_async(h, p, timeout, grab_banners, jitter, progress)

        return await asyncio.gather(*[guarded(h, p) for h, p in tcp_tasks])

    return list(asyncio.run(runner()))

ALIVE_PROBE_PORTS = (22, 80, 135, 443, 445, 3389, 8080)

def preflight_alive(targets, timeout=0.35):
    def check(h):
        for p in ALIVE_PROBE_PORTS:
            try:
                with socket.create_connection((h, p), timeout=timeout):
                    return True
            except OSError:
                continue
        return False

    alive = []
    with ThreadPoolExecutor(max_workers=min(256, max(16, len(targets)))) as pool:
        for h, ok in zip(targets, pool.map(check, targets)):
            if ok:
                alive.append(h)
    return alive

def _cert_name(dn):
    parts = []
    if dn:
        for rdn in dn:
            for _, v in rdn:
                parts.append(v)
    return "/".join(parts)

def _decode_der(der):
    try:
        from ssl import _ssl
        pem = ssl.DER_cert_to_PEM_cert(der)
        fd, path = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(pem)
            return _ssl._test_decode_cert(path)
        finally:
            os.unlink(path)
    except Exception:
        return None

def check_tls(host, port, timeout=3):
    entry = {
        "host": host, "port": port, "tls": False, "protocol": "",
        "subject": "", "issuer": "", "not_after": "", "days_left": None,
        "issues": []
    }
    cert = None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                entry["protocol"] = tls.version()
    except Exception:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    entry["protocol"] = tls.version()
                    der = tls.getpeercert(binary_form=True)
                    cert = _decode_der(der) if der else None
                    entry["issues"].append("Certificate not trusted by system CAs")
        except Exception:
            return entry
    entry["tls"] = True
    if cert:
        entry["subject"] = _cert_name(cert.get("subject"))
        entry["issuer"] = _cert_name(cert.get("issuer"))
        na = cert.get("notAfter")
        if na:
            entry["not_after"] = na
            try:
                days = int((ssl.cert_time_to_seconds(na) - time.time()) // 86400)
                entry["days_left"] = days
                if days < 0:
                    entry["issues"].append("Certificate EXPIRED")
                elif days <= 30:
                    entry["issues"].append(f"Expires in {days} days")
            except Exception:
                pass
        if entry["subject"] and entry["subject"] == entry["issuer"]:
            entry["issues"].append("Self-signed")
    if entry["protocol"] in ("TLSv1", "TLSv1.1", "SSLv3"):
        entry["issues"].append(f"Weak protocol {entry['protocol']}")
    return entry

DEDUCTIONS = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2, "INFO": 0}
CVE_DEDUCT = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3}

def remediation_for(f):
    out = list(REMEDIATION_MAP.get(f["port"], []))
    if not out:
        if f["protocol"] == "tcp":
            out.append(f"sudo ufw deny {f['port']}/tcp")
        else:
            out.append(f"sudo ufw deny {f['port']}/udp")
        out.append("Confirm this service is required; if not, stop and disable it")
    return out

def compute_host_score(hd):
    score = 100
    for f in hd["findings"]:
        score -= DEDUCTIONS.get(f["risk"], 0)
        if f["unexpected"]:
            score -= 4
        for c in f["cves"]:
            score -= CVE_DEDUCT.get(c["severity"], 2)
    for t in hd.get("tls", []):
        score -= 8 * len(t["issues"])
    score -= 3 * len(hd.get("missing_expected_ports", []))
    score = max(0, min(100, score))
    grade = ("A" if score >= 90 else "B" if score >= 80 else
             "C" if score >= 70 else "D" if score >= 60 else "F")
    return score, grade

def enrich(report):
    for host, hd in report["hosts"].items():
        for f in hd["findings"]:
            if not f["mitre"]:
                f["mitre"] = MITRE_MAP.get(f["port"], "")
            f["compliance"] = COMPLIANCE_MAP.get(f["port"], [])
            f["remediation"] = remediation_for(f)
        hd["score"], hd["grade"] = compute_host_score(hd)

def extract_open_state(report):
    state = set()
    for host, hd in report["hosts"].items():
        for f in hd["findings"]:
            state.add((host, f["protocol"], f["port"]))
    return state

def load_baseline(path):
    try:
        with open(path) as fh:
            d = json.load(fh)
        return {tuple(x) for x in d.get("state", [])}, d.get("targets", [])
    except Exception:
        return None, []

def save_baseline(path, state, targets=None):
    with open(path, "w") as fh:
        json.dump({"created": datetime.now(timezone.utc).isoformat(), "targets": sorted(targets or []), "state": [list(x) for x in sorted(state)]}, fh, indent=2)

def detect_drift(prev, curr):
    return sorted(curr - prev), sorted(prev - curr)

def fmt_state(items):
    return ", ".join(f"{h} {pr}/{p}" for (h, pr, p) in items) if items else "none"

def update_history(history, report, cycle, notifier):
    seen_now = {}
    for host, hd in report["hosts"].items():
        for f in hd["findings"]:
            seen_now[(host, f["protocol"], f["port"])] = f.get("banner", "")
    for key, banner in seen_now.items():
        h = history.get(key)
        if h and h.get("last_banner") and banner and banner != h["last_banner"]:
            notifier.send("Banner changed (possible compromise or update)", f"{key[0]} {key[1]}/{key[2]}: {h['last_banner'][:40]!r} -> {banner[:40]!r}", "HIGH")
    for key, h in history.items():
        if key not in seen_now and h.get("seen_cycles") and cycle - h["last_cycle"] == 1 and h["seen_cycles"] <= 2:
            notifier.send("Ephemeral port vanished (possible backdoor/reverse shell)", f"{key[0]} {key[1]}/{key[2]} was open for only {h['seen_cycles']} cycle(s)", "HIGH")
    for key, banner in seen_now.items():
        h = history.setdefault(key, {"first_cycle": cycle, "last_cycle": cycle, "last_banner": banner, "seen_cycles": 0})
        h["last_cycle"] = cycle
        h["seen_cycles"] += 1
        if banner:
            h["last_banner"] = banner

def audit(targets, tcp_ports, udp_ports, workers, timeout, allowlist=None, level_num=2, cfg=None, benchmark=False, with_nmap=False, nmap_spec=""):
    cfg = cfg or SCAN_LEVELS[level_num]
    jitter = cfg.get("jitter", (0.0, 0.0))
    grab_banners = cfg.get("grab_banners", True)
    started = time.time()
    engine = "threads"

    if len(targets) > 16:
        t0 = time.time()
        alive = preflight_alive(targets)
        if alive:
            print(f"  ⚡ Pre-flight: {len(alive)} alive of {len(targets)} hosts ({len(targets) - len(alive)} silent, skipped) in {time.time() - t0:.1f}s")
            targets = alive

    syn_scanner = None
    if cfg.get("syn") and syn_available():
        try:
            syn_scanner = SYNScanner(timeout=max(timeout, 1.0))
            engine = "syn-batched"
        except OSError:
            syn_scanner = None
    if cfg.get("max_workers"):
        workers = max(1, min(workers, cfg["max_workers"]))
    if jitter != (0.0, 0.0):
        tcp_ports = list(tcp_ports)
        random.shuffle(tcp_ports)

    total_probes = (len(tcp_ports) + len(udp_ports)) * len(targets)
    progress = Progress(total_probes)
    results = []

    try:
        tcp_tasks = [(h, p) for h in targets for p in tcp_ports]
        if syn_scanner:
            for h in targets:
                for p, state in syn_scanner.scan_many(h, tcp_ports).items():
                    results.append(_syn_finding(h, p, state))
                    progress.bump()
        elif len(tcp_tasks) > 64:
            engine = "asyncio"
            results.extend(_run_tcp_async(tcp_tasks, workers, timeout, grab_banners, jitter, progress))
        else:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="audit") as pool:
                futures = [pool.submit(scan_tcp_port, h, p, timeout, grab_banners, jitter) for h, p in tcp_tasks]
                for fut in as_completed(futures):
                    results.append(fut.result())
                    progress.bump()
        udp_tasks = [(h, p) for h in targets for p in udp_ports]
        if udp_tasks:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="udp") as pool:
                futures = [pool.submit(scan_udp_port, h, p, timeout) for h, p in udp_tasks]
                for fut in as_completed(futures):
                    results.append(fut.result())
                    progress.bump()
    finally:
        if syn_scanner:
            syn_scanner.close()

    by_host = {}
    for f in results:
        by_host.setdefault(f["host"], []).append(f)

    allowlist = set(allowlist or [])
    hosts = {}
    for h in targets:
        findings = sorted(by_host.get(h, []), key=lambda x: (x["protocol"], x["port"]))
        open_ports = [f["port"] for f in findings if f["state"] in ("open", "open|filtered")]
        for f in findings:
            if f["state"] in ("open", "open|filtered") and allowlist and f["port"] not in allowlist:
                f["unexpected"] = True
                if f["risk"] == "LOW":
                    f["risk"], f["risk_reason"] = "MEDIUM", "Open port not in allowlist"
        missing = sorted(p for p in allowlist if p not in open_ports) if allowlist else []
        hosts[h] = {
            "open_count": len(open_ports), "open_ports": open_ports,
            "missing_expected_ports": missing, "tls": [],
            "findings": [f for f in findings if f["state"] in ("open", "open|filtered")]
        }

    if cfg.get("tls", False):
        for h in targets:
            for f in hosts[h]["findings"]:
                if f["protocol"] == "tcp" and f["port"] in TLS_PORTS:
                    hosts[h]["tls"].append(check_tls(h, f["port"]))

    report = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "level": f"{level_num} {cfg['name']}",
        "worker_threads": workers,
        "syn_scan_used": syn_scanner is not None,
        "targets": targets,
        "tcp_ports_scanned": len(tcp_ports),
        "udp_ports_scanned": len(udp_ports),
        "hosts": hosts,
    }
    enrich(report)

    if benchmark:
        elapsed = time.time() - started
        b = {
            "elapsed_sec": round(elapsed, 2), "probes": total_probes,
            "probes_per_sec": round(total_probes / elapsed, 1) if elapsed else 0,
            "engine": engine
        }
        if with_nmap and shutil.which("nmap") and tcp_ports:
            try:
                t0 = time.time()
                subprocess.run(["nmap", "-Pn", "-T4", "-p", nmap_spec] + targets, capture_output=True, timeout=max(120, elapsed * 4))
                b["nmap_elapsed_sec"] = round(time.time() - t0, 2)
            except Exception as e:
                b["nmap_error"] = str(e)[:100]
        report["benchmark"] = b
    return report

def _vis_len(s):
    return len(ANSI_RE.sub("", s))

def box_table(headers, rows, style=None):
    rows = [[str(c) for c in r] for r in rows]
    widths = [max([len(h)] + [_vis_len(r[i]) for r in rows]) for i, h in enumerate(headers)]
    styled = []
    for r in rows:
        styled.append([style[i](r[i]) if style and i in style else r[i] for i in range(len(r))])

    def fmt(cells):
        out = []
        for c, w in zip(cells, widths):
            out.append(" " + c + " " * (w - _vis_len(c)) + " ")
        return "│" + "│".join(out) + "│"

    top = "┌" + "┬".join("─" * (w + 2) for w in widths) + "┐"
    mid = "├" + "┼".join("─" * (w + 2) for w in widths) + "┤"
    bot = "└" + "┴".join("─" * (w + 2) for w in widths) + "┘"
    return "\n".join([top, fmt(headers), mid] + [fmt(r) for r in styled] + [bot])

def grade_card(host, hd):
    g = hd.get("grade", "?")
    col = GRADE_COLOR.get(g, "")
    unexp = sum(1 for f in hd["findings"] if f["unexpected"])
    warn = f"  ! {unexp} unexpected" if unexp else ""
    lines = [
        f"HOST   {host}",
        f"SCORE  {hd.get('score', '-')}/100   GRADE [{g}]{warn}",
        f"OPEN   {hd['open_count']} port(s)",
    ]
    inner = max(len(l) for l in lines) + 2
    top = "  " + col + "┌" + "─" * inner + "┐"
    bot = "  └" + "─" * inner + "┘" + RESET
    body = "\n".join("  " + col + "│ " + l.ljust(inner - 2) + " │" for l in lines)
    return top + "\n" + body + "\n" + bot

def print_report(report):
    print(f"\n  ═════ PORT AUDIT @ {report['scanned_at']} ═════")
    cyc = f" | Cycle: {report['cycle']}" if report.get("cycle") else ""
    print(f"  Level: {report['level']} | Threads: {report['worker_threads']} | Targets: {len(report['targets'])} | TCP: {report['tcp_ports_scanned']} | UDP: {report['udp_ports_scanned']}{cyc}")
    if report.get("benchmark"):
        b = report["benchmark"]
        line = f"  Benchmark: {b['probes']} probes in {b['elapsed_sec']}s ({b['probes_per_sec']} probes/sec, engine: {b.get('engine', '?')})"
        if "nmap_elapsed_sec" in b:
            line += f" | nmap: {b['nmap_elapsed_sec']}s"
        print(line)
    for host, hd in report["hosts"].items():
        print(grade_card(host, hd))
        if hd["findings"]:
            ordered = sorted(hd["findings"], key=lambda f: RISK_ORDER.get(f["risk"], 5))
            rows = []
            for f in ordered:
                intel = "; ".join(
                    ([("CVE: " + ",".join(c["id"] for c in f["cves"]))] if f["cves"] else [])
                    + ([f["mitre"]] if f["mitre"] else [])
                    + (["/".join(f["compliance"])] if f["compliance"] else [])
                    + ([f["banner"][:45]] if f["banner"] else [f["risk_reason"]])
                )
                rows.append([f"{f['port']}/{f['protocol']}", f["risk"], f["service"] + (" [UNEXPECTED]" if f["unexpected"] else ""), intel[:95]])
            risk_style = lambda c: SEV_COLOR.get(c.strip(), "") + c + RESET if c.strip() in SEV_COLOR else c
            table = box_table(["PORT", "RISK", "SERVICE", "INTEL"], rows, style={1: risk_style})
            print("  " + table.replace("\n", "\n  "))
            for f in [x for x in ordered if x["risk"] in ("CRITICAL", "HIGH")][:3]:
                print(f"  ↳ FIX {f['port']}/{f['protocol']}: {f['remediation'][0]}")
        else:
            print("  No open/filtered ports detected.")
        for t in hd.get("tls", []):
            issues = "; ".join(t["issues"]) or "OK"
            print(f"  🔐 TLS {t['port']}: {t['subject'] or '(no cert)'} | {t['protocol']} | days left: {t['days_left']} | {issues}")
        if hd["missing_expected_ports"]:
            print(f"  ⚠️ WARNING expected-but-closed: {hd['missing_expected_ports']}")
    print()

CSV_FIELDS = [
    "timestamp", "cycle", "host", "protocol", "port", "state", "service",
    "banner", "software", "version", "cve_ids", "risk", "risk_reason",
    "unexpected", "mitre", "compliance", "score", "grade", "level", "threads"
]

def write_csv(report, path, append=False):
    file_exists = os.path.exists(path)
    mode = "a" if append else "w"
    with open(path, mode, newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        if not (append and file_exists):
            w.writeheader()
        for host, hd in report["hosts"].items():
            for f in hd["findings"]:
                w.writerow({
                    "timestamp": report.get("scanned_at", ""),
                    "cycle": report.get("cycle", ""), "host": host,
                    "protocol": f["protocol"], "port": f["port"], "state": f["state"],
                    "service": f["service"], "banner": f["banner"],
                    "software": f["software"], "version": f["version"],
                    "cve_ids": "|".join(c["id"] for c in f["cves"]),
                    "risk": f["risk"], "risk_reason": f["risk_reason"],
                    "unexpected": f["unexpected"], "mitre": f["mitre"],
                    "compliance": "|".join(f["compliance"]),
                    "score": hd.get("score", ""), "grade": hd.get("grade", ""),
                    "level": report.get("level", ""),
                    "threads": report.get("worker_threads", ""),
                })
    print(f"  ↳ CSV saved to: {path}")

def save_json(report, path):
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"  ↳ JSON saved to: {path}")

HTML_CSS = """
body{font-family:'Segoe UI',Arial,sans-serif;margin:24px;background:#f5f6f7;color:#222}
h1{font-size:20px}.meta{color:#555;font-size:13px;margin-bottom:16px}
table{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.12)}
th,td{padding:8px 10px;border-bottom:1px solid #e2e2e2;text-align:left;font-size:13px}
th{background:#2c3e50;color:#fff}.badge{color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
"""

def save_html(report, path):
    def esc(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    colors = {"CRITICAL": "#7a0c0c", "HIGH": "#c0392b", "MEDIUM": "#e67e22", "LOW": "#27ae60", "INFO": "#7f8c8d"}
    rows = []
    for host, hd in report["hosts"].items():
        for f in hd["findings"]:
            bg = colors.get(f["risk"], "#7f8c8d")
            un = " <b>[UNEXPECTED]</b>" if f["unexpected"] else ""
            intel = " ".join([esc(",".join(c["id"] for c in f["cves"])), esc(f["mitre"]), esc(f["banner"] or f["risk_reason"])])
            rows.append(
                f"<tr><td>{esc(host)}</td><td>{f['port']}</td><td>{f['protocol']}</td>"
                f"<td><span class='badge' style='background:{bg}'>{f['risk']}</span></td>"
                f"<td>{esc(f['service'])}</td><td>{intel}{un}</td></tr>"
            )
    scores = ", ".join(f"{h}: {d.get('score','-')}/100 ({d.get('grade','?')})" for h, d in report["hosts"].items())
    meta = f"Scanned: {esc(report['scanned_at'])} | Level: {esc(report['level'])} | Scores: {esc(scores)}"
    html = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>Port Audit Report</title><style>" + HTML_CSS + "</style></head><body>"
        "<h1>Port Audit Report</h1><div class='meta'>" + meta + "</div>"
        "<table><thead><tr><th>Host</th><th>Port</th><th>Proto</th><th>Risk</th>"
        "<th>Service</th><th>Intel</th></tr></thead><tbody>"
        + ("\n".join(rows) or "<tr><td colspan='6'>No findings</td></tr>")
        + "</tbody></table></body></html>"
    )
    with open(path, "w") as fh:
        fh.write(html)
    print(f"  ↳ HTML saved to: {path}")

def collect_unexpected(report):
    out = []
    for host, hd in report["hosts"].items():
        for f in hd["findings"]:
            if f["unexpected"]:
                out.append((host, f["protocol"], f["port"]))
    return sorted(out)

def run_watch(opts):
    notifier, stop, trigger = opts["notifier"], opts["stop"], opts["trigger"]
    with DASH_LOCK:
        DASH_STATE["watch"] = True
    notifier.send("Watch mode started", f"Monitoring {len(opts['targets'])} host(s) every {opts['interval']}s (level {opts['cfg']['name']})", "INFO")

    baseline = None
    if opts["baseline_file"] and os.path.exists(opts["baseline_file"]):
        baseline, saved_targets = load_baseline(opts["baseline_file"])
        if baseline is not None and saved_targets and set(saved_targets) != set(opts["targets"]):
            notifier.send("Baseline ignored", "saved for a different target set; re-baselining", "INFO")
            baseline = None
        elif baseline is not None:
            notifier.send("Baseline loaded from disk", f"{len(baseline)} approved port(s) ({opts['baseline_file']})", "INFO")
    history, cycle = {}, 0

    while not stop.is_set():
        cycle += 1
        report = audit(
            opts["targets"], opts["tcp_ports"], opts["udp_ports"],
            opts["workers"], opts["timeout"], opts["allowlist"],
            level_num=opts["level_num"], cfg=opts["cfg"],
            benchmark=opts["benchmark"]
        )
        report["cycle"] = cycle
        report["system"] = opts["info"]
        update_dash_state(report)
        print_report(report)

        write_csv(report, opts["csv"], append=(cycle > 1))
        save_json(report, opts["json_out"])
        if not opts["no_html"]:
            save_html(report, opts["html"])

        unexpected = collect_unexpected(report)
        if unexpected:
            notifier.send("Unexpected open ports", fmt_state(unexpected), "HIGH", {"unexpected": [list(x) for x in unexpected]})

        update_history(history, report, cycle, notifier)

        curr = extract_open_state(report)
        if baseline is None:
            baseline = curr
            notifier.send("Baseline established", f"{len(curr)} open port(s) recorded", "INFO")
        else:
            opened, closed = detect_drift(baseline, curr)
            if opened or closed:
                sev = "CRITICAL" if opened else "MEDIUM"
                notifier.send("Port drift detected", f"NEWLY OPENED: {fmt_state(opened)} | NEWLY CLOSED: {fmt_state(closed)}", sev, {"opened": [list(x) for x in opened], "closed": [list(x) for x in closed]})
                baseline = curr

        if opts["baseline_file"]:
            save_baseline(opts["baseline_file"], baseline, opts["targets"])

        if opts["max_cycles"] and cycle >= opts["max_cycles"]:
            notifier.send("Watch mode stopped", f"reached {opts['max_cycles']} cycle(s)", "INFO")
            break

        deadline = time.time() + opts["interval"]
        while time.time() < deadline and not stop.is_set():
            if trigger.is_set():
                trigger.clear()
                notifier.send("Manual scan triggered", "via dashboard/API", "INFO")
                break
            time.sleep(0.25)

def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            try:
                lo, hi = int(lo), int(hi)
            except ValueError:
                continue
            ports.update(range(lo, hi + 1))
        else:
            try:
                ports.add(int(part))
            except ValueError:
                continue
    return sorted(p for p in ports if 0 < p < 65536)

def expand_targets(spec):
    targets = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
            except ValueError:
                raise SystemExit(f"Invalid network: {part}")
            targets.extend(str(ip) for ip in net.hosts() or [net.network_address])
        else:
            targets.append(part)
    seen, out = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            out.append(t)
    if len(out) > MAX_SWEEP_HOSTS:
        raise SystemExit(f"Too many hosts ({len(out)}); max {MAX_SWEEP_HOSTS}.")
    return out

def confirm_plan(targets, tcp_ports, udp_ports, workers, level_num, cfg, syn_on, watch=False, dash_port=None):
    total = (len(tcp_ports) + len(udp_ports)) * len(targets)
    print("\n  ╭─ Execution Plan ───────────────────────────────────────────╮")
    print(f"  │  Level       : {level_num} {cfg['name']:<42} │")
    if level_num == 4:
        tech = 'SYN half-open (batched)' if syn_on else 'quiet connect (rate-limited)'
        print(f"  │  Technique   : {tech:<42} │")
    print(f"  │  Targets     : {len(targets):<42} │")
    print(f"  │  TCP Ports   : {len(tcp_ports):<10} UDP Ports: {len(udp_ports):<21} │")
    if len(tcp_ports) >= 65535:
        print("  │  Coverage    : ALL 65,535 TCP ports                        │")
    print(f"  │  Threads     : {workers:<42} │")
    print(f"  │  Total Probes: {total:<42,} │")
    if total > 20000:
        est_min = total / (600 if len(targets) == 1 else 350) / 60
        print(f"  │  Est. Time   : ~{max(est_min, 0.5):.1f} min(s){'':<32} │")
    if watch:
        print("  │  Mode        : WATCH (continuous monitoring)               │")
    if dash_port:
        print(f"  │  Dashboard   : http://127.0.0.1:{dash_port:<26} │")
    print("  ╰─────────────────────────────────────────────────────────────╯")
    if not sys.stdin.isatty():
        return True
    try:
        ans = input("\n  ❯ Proceed with scan? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return ans in ("", "y", "yes")

class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

class ReusableUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True

class QuietHandler(socketserver.BaseRequestHandler):
    def handle(self):
        pass

class BannerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.sendall(b"SSH-2.0-OpenSSH_7.4p1 TestServer\r\n")
        except OSError:
            pass

class UDPTestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(b"UDPECHO-TEST-OK", self.client_address)

def make_http_handler():
    from http.server import BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(200)
            self.send_header("Server", "AuditTestHTTP/1.0")
            self.end_headers()

        def do_GET(self):
            self.do_HEAD()

        def log_message(self, *args):
            pass

    return Handler

def start_tcp_listener(port, handler_cls):
    srv = ReusableTCPServer(("127.0.0.1", port), handler_cls)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

def start_tls_listener(port, certfile, keyfile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    raw = socket.socket()
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw.bind(("127.0.0.1", port))
    raw.listen(5)

    def loop():
        while True:
            try:
                c, _ = raw.accept()
            except OSError:
                break
            try:
                s = ctx.wrap_socket(c, server_side=True)
                s.close()
            except Exception:
                try:
                    c.close()
                except OSError:
                    pass

    threading.Thread(target=loop, daemon=True).start()
    return raw

def run_self_test():
    enable_windows_console()
    info = system_info()
    print_banner(info)
    print_system_info(info)
    print("  ⚡ RAW SYN scan capability:", syn_available())
    print("  ⚡ Starting local test server stack...")
    servers = [
        start_tcp_listener(9101, QuietHandler),
        start_tcp_listener(9102, BannerHandler),
        start_tcp_listener(9103, make_http_handler()),
    ]
    udp_srv = ReusableUDPServer(("127.0.0.1", 9105), UDPTestHandler)
    threading.Thread(target=udp_srv.serve_forever, daemon=True).start()
    servers.append(udp_srv)

    tls_raw = None
    if shutil.which("openssl"):
        try:
            tmp = tempfile.mkdtemp()
            cert, key = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key, "-out", cert, "-days", "30",
                "-nodes", "-subj", "/CN=localhost"
            ], capture_output=True, check=True)
            tls_raw = start_tls_listener(9107, cert, key)
            TLS_PORTS.add(9107)
            print("  ⚡ TLS listener online (port 9107)")
        except Exception as e:
            print(f"  ⚠️ TLS self-test bypassed ({e})")
    time.sleep(0.4)

    try:
        tcp_ports = DEFAULT_PORTS + [9101, 9102, 9103] + ([9107] if tls_raw else [])
        allowlist = {9101, 9103, 9105} | ({9107} if tls_raw else set())
        report = audit(["127.0.0.1"], tcp_ports, [9105, 9106], info["default_worker_threads"], 0.4, allowlist, level_num=2, benchmark=True)
        report["system"] = info
        update_dash_state(report)
        print_report(report)
        save_json(report, "audit_report.json")
        save_html(report, "audit_report.html")
        write_csv(report, "audit_report.csv")

        hd = report["hosts"]["127.0.0.1"]
        for p in (9101, 9102, 9103, 9105):
            assert p in hd["open_ports"], f"failed to detect {p}"
        assert 80 not in hd["open_ports"], "false positive on port 80"
        f9102 = next(f for f in hd["findings"] if f["port"] == 9102)
        assert f9102["unexpected"], "allowlist violation not flagged"
        print("  ✔ Core engine & allowlist validation")

        assert f9102["software"] == "openssh" and f9102["version"] == "7.4p1"
        assert any(c["id"] == "CVE-2018-15473" for c in f9102["cves"]), "CVE match failed"
        print(f"  ✔ CVE analysis engine ({f9102['software']} {f9102['version']})")

        assert hd["score"] < 100 and hd["grade"] in "ABCDF"
        assert f9102["remediation"], "remediation missing"
        assert MITRE_MAP[3389] == "T1021.001 RDP"
        assert COMPLIANCE_MAP[23] == ["PCI-DSS 2.2.2", "CIS 4.5"]
        print(f"  ✔ Risk Scoring system (score={hd['score']}, grade={hd['grade']})")

        if tls_raw:
            t = next(t for t in hd["tls"] if t["port"] == 9107)
            assert t["tls"] and t["days_left"] is not None and t["days_left"] > 0
            assert "Self-signed" in t["issues"]
            print(f"  ✔ TLS Inspector (certificate expiry & trust chain check)")

        with open("audit_report.csv") as fh:
            lines = fh.read().splitlines()
        assert len(lines) >= 2 and lines[0].startswith("timestamp")
        print(f"  ✔ CSV/JSON/HTML Export drivers")

        save_baseline("selftest_baseline.json", extract_open_state(report), ["127.0.0.1"])
        loaded, saved_targets = load_baseline("selftest_baseline.json")
        assert saved_targets == ["127.0.0.1"] and loaded == extract_open_state(report), "baseline round-trip failed"
        opened, closed = detect_drift(loaded, loaded - {("127.0.0.1", "tcp", 9101)})
        assert opened == [] and closed == [("127.0.0.1", "tcp", 9101)]
        print("  ✔ Baseline state persistence & drift detector")

        n = Notifier(notify_file="selftest_notifications.log")
        n.send("Self-test", "notification channel OK", "INFO")
        assert os.path.exists("selftest_notifications.log")
        print("  ✔ Notification system (file/dashboard feed)")

        hist = {}
        fake1 = {"hosts": {"h": {"findings": [{"host": "h", "protocol": "tcp", "port": 1, "banner": "AAA"}]}}}
        fake2 = {"hosts": {"h": {"findings": [{"host": "h", "protocol": "tcp", "port": 1, "banner": "BBB"}, {"host": "h", "protocol": "tcp", "port": 2, "banner": ""}]}}}
        fake3 = {"hosts": {"h": {"findings": [{"host": "h", "protocol": "tcp", "port": 1, "banner": "BBB"}]}}}
        update_history(hist, fake1, 1, n)
        update_history(hist, fake2, 2, n)
        update_history(hist, fake3, 3, n)
        log = open("selftest_notifications.log").read()
        assert "Banner changed" in log and "Ephemeral" in log
        print("  ✔ Anomaly monitoring (banner alteration & ephemeral ports)")

        stealth_cfg = dict(SCAN_LEVELS[4], syn=False)
        rep2 = audit(["127.0.0.1"], [9101, 9102, 9103, 9104], [], 8, 0.4, level_num=4, cfg=stealth_cfg)
        hd2 = rep2["hosts"]["127.0.0.1"]
        assert sorted(hd2["open_ports"]) == [9101, 9102, 9103]
        assert all(not f["banner"] for f in hd2["findings"])
        print(f"  ✔ Stealth scanning strategy")

        rep3 = audit(["127.0.0.1"], list(range(9100, 9170)), [], 16, 0.3, level_num=2)
        hd3 = rep3["hosts"]["127.0.0.1"]
        assert {9101, 9102, 9103} <= set(hd3["open_ports"])
        f9102a = next(f for f in hd3["findings"] if f["port"] == 9102)
        assert f9102a["software"] == "openssh" and any(c["id"] == "CVE-2018-15473" for c in f9102a["cves"])
        print("  ✔ Asyncio execution routine")

        assert SCAN_LEVELS[5]["tcp_default"] == "all" and len(ALL_TCP_PORTS) == 65535
        print("  ✔ Full 65,535-port range profiler")

        print("\n  ✨ ALL SYSTEM TESTS PASSED SUCCESSFULLY ✨\n")
    finally:
        for srv in servers:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                pass
        if tls_raw:
            try:
                tls_raw.close()
            except OSError:
                pass

def main():
    enable_windows_console()
    ap = argparse.ArgumentParser(description="Advanced port auditor: levels, TLS, CVE, scoring, watch, dashboard, notifications, CSV/JSON/HTML")
    ap.add_argument("--host", help="Host or comma-separated hosts")
    ap.add_argument("--cidr", help="CIDR network(s), e.g. 192.168.1.0/24")
    ap.add_argument("--ports", help="TCP ports, e.g. '22,80,8000-8100'")
    ap.add_argument("--range", help="Full TCP range shorthand, e.g. '1-1024'")
    ap.add_argument("--all-ports", action="store_true", help="Scan ALL 65,535 TCP ports (overrides --ports/--range)")
    ap.add_argument("--udp-ports", help="Specific UDP ports, e.g. '53,161'")
    ap.add_argument("--level", type=int, choices=sorted(SCAN_LEVELS))
    ap.add_argument("--allowlist", default="", help="Expected open ports, e.g. '22,443'")
    ap.add_argument("--workers", type=int, help="Worker threads (skips prompt)")
    ap.add_argument("--timeout", type=float, default=None, help="Per-probe timeout in seconds")
    ap.add_argument("--yes", action="store_true", help="Skip confirmation prompt")
    ap.add_argument("--watch", action="store_true", help="Continuous monitoring mode")
    ap.add_argument("--watch-interval", type=int, default=60, help="Seconds between scans in watch mode")
    ap.add_argument("--cycles", type=int, default=0, help="Stop watch mode after N cycles")
    ap.add_argument("--webhook", help="Webhook URL for notifications")
    ap.add_argument("--notify-file", help="Append notifications to file")
    ap.add_argument("--baseline-file", default="baseline.json", help="Persist port baseline file")
    ap.add_argument("--dashboard", action="store_true", help="Serve web dashboard")
    ap.add_argument("--dash-port", type=int, default=8099)
    ap.add_argument("--benchmark", action="store_true", help="Report probes/sec")
    ap.add_argument("--with-nmap", action="store_true", help="Compare with nmap speed")
    ap.add_argument("--strict", action="store_true", help="Exit code 2 if unexpected ports exist")
    ap.add_argument("--csv-out", default="audit_report.csv")
    ap.add_argument("--json-out", default="audit_report.json")
    ap.add_argument("--html-out", default="audit_report.html")
    ap.add_argument("--no-html", action="store_true")
    args = ap.parse_args()

    specs = [s for s in (args.host, args.cidr) if s]
    if not specs:
        run_self_test()
        return

    info = system_info()
    print_banner(info)
    print_system_info(info)

    level_num = args.level if args.level else prompt_level()
    cfg = SCAN_LEVELS[level_num]
    print(f"\n  🎯 Active Level: [{level_num}] {cfg['name']} — {cfg['desc']}")
    if level_num == 4:
        if syn_available():
            print("  ⚡ Raw sockets available -> employing batched half-open SYN strategy.")
        else:
            print("  ⚡ Raw sockets unavailable -> defaulting to rate-limited quiet connect scan.")

    sys_max = info["max_worker_threads"]
    eff_max = min(sys_max, cfg["max_workers"]) if cfg["max_workers"] else sys_max
    default_w = min(info["default_worker_threads"], eff_max)
    if cfg["max_workers"]:
        print(f"  ℹ Level {level_num} limits thread pool to {cfg['max_workers']} for stealth.")
    if args.workers:
        workers = max(1, min(args.workers, eff_max))
    else:
        workers = prompt_workers(default_w, eff_max)
    print(f"  ⚡ Workers initialized: {workers} threads.")

    targets = expand_targets(",".join(specs))
    if args.all_ports:
        tcp_ports = list(ALL_TCP_PORTS)
        print("  ⚡ Target Range: ALL 65,535 TCP ports.")
    else:
        tcp_ports = parse_ports(args.ports or args.range or "")
        if not tcp_ports:
            td = cfg["tcp_default"]
            if td == "full":
                tcp_ports = list(range(1, 1025))
            elif td == "all":
                tcp_ports = list(ALL_TCP_PORTS)
            else:
                tcp_ports = list(td)
    udp_ports = []
    if args.udp_ports:
        udp_ports = parse_ports(args.udp_ports)
    elif cfg["udp_default"] == "common":
        udp_ports = sorted(UDP_PORTS)
    allowlist = set(parse_ports(args.allowlist))

    if args.timeout is None:
        if len(tcp_ports) > 10000:
            args.timeout = 0.35
            print(f"  ℹ All-port profile active -> probe timeout scaled to {args.timeout}s.")
        else:
            args.timeout = 0.6

    syn_on = cfg.get("syn", False) and syn_available()
    dash_port = args.dash_port if args.dashboard else None
    if not args.yes and not confirm_plan(targets, tcp_ports, udp_ports, workers, level_num, cfg, syn_on, watch=args.watch, dash_port=dash_port):
        print("\n  ❌ Scan cancelled by operator.")
        return

    notifier = Notifier(webhook=args.webhook, notify_file=args.notify_file)
    stop = threading.Event()
    trigger = threading.Event()
    if args.dashboard:
        start_dashboard(args.dash_port, trigger)
        print(f"  🌐 Dashboard online: http://127.0.0.1:{args.dash_port}")
        try:
            webbrowser.open(f"http://127.0.0.1:{args.dash_port}")
        except Exception:
            pass

    baseline_file = args.baseline_file or None
    nmap_spec = ",".join(str(p) for p in tcp_ports[:200]) if args.with_nmap else ""

    def do_scan(cycle=None):
        rep = audit(
            targets, tcp_ports, udp_ports, workers, args.timeout,
            allowlist, level_num=level_num, cfg=cfg,
            benchmark=args.benchmark or args.with_nmap,
            with_nmap=args.with_nmap, nmap_spec=nmap_spec
        )
        if cycle:
            rep["cycle"] = cycle
        rep["system"] = info
        update_dash_state(rep)
        print_report(rep)
        return rep

    opts = {
        "notifier": notifier, "stop": stop, "trigger": trigger,
        "targets": targets, "tcp_ports": tcp_ports, "udp_ports": udp_ports,
        "workers": workers, "timeout": args.timeout, "allowlist": allowlist,
        "level_num": level_num, "cfg": cfg,
        "benchmark": args.benchmark or args.with_nmap,
        "info": info, "csv": args.csv_out, "json_out": args.json_out,
        "html": args.html_out, "no_html": args.no_html,
        "baseline_file": baseline_file, "max_cycles": args.cycles,
        "interval": max(5, args.watch_interval),
    }

    if args.watch:
        try:
            run_watch(opts)
        except KeyboardInterrupt:
            notifier.send("Watch mode stopped", "interrupted (Ctrl-C)", "INFO")
        return

    report = do_scan()
    write_csv(report, args.csv_out)
    save_json(report, args.json_out)
    if not args.no_html:
        save_html(report, args.html_out)

    unexpected = collect_unexpected(report)
    if unexpected:
        notifier.send("Unexpected open ports", fmt_state(unexpected), "HIGH", {"unexpected": [list(x) for x in unexpected]})

    if baseline_file:
        curr = extract_open_state(report)
        saved, saved_targets = load_baseline(baseline_file)
        if saved is None or (saved_targets and set(saved_targets) != set(targets)):
            save_baseline(baseline_file, curr, targets)
            reason = "created" if saved is None else "target set changed; re-baselined"
            notifier.send("Baseline saved", f"{len(curr)} approved port(s) -> {baseline_file} ({reason})", "INFO")
        else:
            opened, closed = detect_drift(saved, curr)
            if opened or closed:
                sev = "CRITICAL" if opened else "MEDIUM"
                notifier.send("Drift vs saved baseline", f"NEWLY OPENED: {fmt_state(opened)} | NEWLY CLOSED: {fmt_state(closed)}", sev, {"opened": [list(x) for x in opened], "closed": [list(x) for x in closed]})
            else:
                notifier.send("Baseline check passed", "matches approved state", "INFO")

    if args.dashboard:
        print("\n  🌐 Dashboard monitoring active. Trigger manual re-scans via web UI.")
        try:
            while not stop.is_set():
                if trigger.is_set():
                    trigger.clear()
                    notifier.send("Manual scan triggered", "via dashboard Scan Now", "INFO")
                    report = do_scan()
                    write_csv(report, args.csv_out, append=True)
                    save_json(report, args.json_out)
                    if not args.no_html:
                        save_html(report, args.html_out)
                time.sleep(0.25)
        except KeyboardInterrupt:
            print("\n  Exiting.")
        return

    if args.strict and unexpected:
        print("  ❌ Strict mode enabled: unexpected ports discovered (Exit Code 2)")
        sys.exit(2)

if __name__ == "__main__":
    main()