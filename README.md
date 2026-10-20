# Port Auditor
Advanced TCP/UDP network exposure auditor with security scoring, CVE fingerprinting, continuous monitoring, and a live web dashboard.

Zero dependencies — runs on the Python standard library only.

Features
5 scan levels: QUICK, STANDARD, DEEP, STEALTH, FULL (all 65,535 ports)
Async engine for large scans (500–1000+ probes/sec), threads for small scans
SYN half-open stealth scanning on Linux (root), silent fallback elsewhere
Service banners, software + version fingerprinting, CVE matching
TLS certificate checks: expiry, self-signed, weak protocols
Security score (0–100) and A–F grade per host
MITRE ATT&CK mapping, PCI-DSS / CIS compliance tags
One-line remediation commands for every finding
Watch mode: baseline drift, banner changes, ephemeral-port detection
Notifications: console, log file, Slack-compatible webhook, audible alarm
Live web dashboard with grade donuts, score trend, alert feed, Scan Now
CSV / JSON / HTML reports, benchmark mode, CI gate (--strict)
Requirements
Python 3.8 or newer (tested on 3.15)
Windows / Linux / macOS
No pip installs required
Quick Start
python port1.py


With no arguments the tool runs a full self-test against local test
listeners and prints SELF-TEST PASSED when everything works.

Scan your own machine:

python port1.py --host 127.0.0.1 --yes


## Scan Levels

| Level | Name     | Coverage                                    |
|-------|----------|---------------------------------------------|
| 1     | QUICK    | Top ~20 TCP ports, fastest                  |
| 2     | STANDARD | Common ports + banners + TLS (default)      |
| 3     | DEEP     | Full 1–1024 + common UDP + banners + TLS    |
| 4     | STEALTH  | SYN if root, else slow quiet connect scan   |
| 5     | FULL     | ALL 65,535 TCP ports + banners + TLS        |

Pick a level interactively or pass `--level N`.
`--all-ports` forces a full 65,535-port scan with any level.

## Finding Live Hosts on Your Network

1. Get your subnet from `ipconfig` (e.g. 192.168.1.0/24)
2. Sweep:

python port1.py --cidr 192.168.1.0/24 --level 1 --yes


A pre-flight check skips silent hosts automatically. Hosts with open
ports appear in the report and in `audit_report.csv`.

## Continuous Monitoring (Watch Mode)

python port1.py --host 127.0.0.1 --watch --watch-interval 15 --dashboard --notify-file alerts.log


- Scans on an interval and compares against an approved baseline
- Alerts on newly opened ports, newly closed ports, banner changes,
  and ephemeral ports that vanish (possible backdoors)
- Baseline persists to `baseline.json` and is tied to the target set
- Dashboard opens automatically at http://127.0.0.1:8099

## Notifications

| Flag            | Effect                                    |
|-----------------|-------------------------------------------|
| `--notify-file` | Append alerts to a log file               |
| `--webhook`     | POST JSON alerts to a URL (Slack-ready)   |
| (built-in)      | CRITICAL alerts beep on Windows           |

## Reports

Every scan writes:

- `audit_report.csv` — flat findings, spreadsheet-ready
- `audit_report.json` — full structured report
- `audit_report.html` — styled report for sharing (disable with `--no-html`)

## Automation / CI

python port1.py --host 10.0.0.5 --level 2 --yes --strict --no-html


Exit codes: `0` clean, `2` unexpected open ports found.
Pair with `--allowlist 22,443` to define approved ports.

## Performance

`--benchmark` reports probes/sec and the engine used.
Typical results on modest hardware: ~500 probes/sec single host,
higher across sweeps thanks to the async engine.

## CLI Reference

| Flag                | Description                                  |
|---------------------|----------------------------------------------|
| `--host`            | Host or comma-separated hosts                |
| `--cidr`            | Network range, e.g. 192.168.1.0/24           |
| `--ports`           | TCP ports, e.g. `22,80,8000-8100`            |
| `--range`           | TCP range shorthand, e.g. `1-1024`           |
| `--all-ports`       | Scan all 65,535 TCP ports                    |
| `--udp-ports`       | Specific UDP ports, e.g. `53,161`            |
| `--level`           | Scan level 1–5                               |
| `--allowlist`       | Expected open ports                          |
| `--workers`         | Worker threads                               |
| `--timeout`         | Per-probe timeout in seconds                 |
| `--yes`             | Skip confirmation prompt                     |
| `--watch`           | Continuous monitoring mode                   |
| `--watch-interval`  | Seconds between watch scans                  |
| `--cycles`          | Stop watch after N cycles                    |
| `--dashboard`       | Serve the live web dashboard                 |
| `--dash-port`       | Dashboard port (default 8099)                |
| `--notify-file`     | Log notifications to file                    |
| `--webhook`         | Notification webhook URL                     |
| `--baseline-file`   | Baseline persistence path                    |
| `--benchmark`       | Report probes/sec                            |
| `--with-nmap`       | Compare timing against nmap if installed     |
| `--strict`          | Exit code 2 on unexpected ports              |
| `--csv-out/--json-out/--html-out` | Custom report paths            |
| `--no-html`         | Skip HTML report                             |

## Notes

- UDP `open|filtered` means the port did not refuse the probe; this is
  honest reporting, not a false positive.
- SYN scanning requires raw sockets (root on Linux). On Windows the
  tool automatically falls back to quiet connect scans.
- Only audit systems you own or are explicitly authorized to test.

## License

MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Cammands Cheatsheet

python port1.py                                                                                   Self-test (no arguments)

python port1.py --host 127.0.0.1                                                      (Interactive scan of one host)  python port1.py --host 127.0.0.1 --level 2 --yes                 Standard scan, skip prompts python port1.py --host 127.0.0.1 --range 1-1024 --yes Custom range scan python port1.py --host 127.0.0.1 --ports 22,80,443     Specific ports only python port1.py --host 127.0.0.1 --all-ports --yes     ALL 65,535 ports

python port1.py --cidr 192.168.1.0/24 --level 1 --yes Find live hosts on network
python port1.py --cidr 192.168.1.0/24 --all-ports --level 1 --yes   Full sweep

python port1.py --host 127.0.0.1 --watch --watch-interval 15 --dashboard --notify-file alerts.log
python port1.py --host 127.0.0.1 --level 3 --yes --benchmark
python port1.py --host 127.0.0.1 --level 2 --yes --strict --no-html
python port1.py --host 127.0.0.1 --allowlist 135,445 --yes
