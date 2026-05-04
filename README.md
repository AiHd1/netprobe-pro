# NetProbe Pro 🔍

> Advanced port scanner with risk assessment and actionable security recommendations.

![Python](https://img.shields.io/badge/Python-3.6+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

Most port scanners just tell you what's open. **NetProbe Pro tells you what it means** — every open port gets a risk level, an explanation, and a specific recommendation to fix it.

---

## What makes it different

- **Risk scoring** — every open port is rated CRITICAL / HIGH / MEDIUM / LOW
- **Plain-English explanations** — no technical jargon, just "this port is dangerous because..."
- **Auto-generated recommendations** — tells you exactly what to do next
- **Fast** — 100 parallel threads, scans 1000+ ports in ~15 seconds
- **Export ready** — saves JSON and CSV reports you can share with clients
- **Zero dependencies** — runs on any machine with Python 3.6+

---

## Quick start

```bash
# Clone the repo
git clone https://github.com/yourusername/netprobe-pro
cd netprobe-pro

# Run a scan
python port_scanner.py 192.168.1.1

# Or run interactively
python port_scanner.py
# → Enter IP or domain: example.com
```

No pip install needed. Just Python.

---

## Example output

```
🔍 NetProbe Pro — Scanning example.com (93.184.216.34)
📊 Ports to check: 1050
⚡ Threads: 100

  🟢 Port    80 | HTTP         | MEDIUM   | Unencrypted web traffic
  🟢 Port   443 | HTTPS        | LOW      | Encrypted web — OK
  🔴 Port  3306 | MySQL        | CRITICAL | Database exposed to the internet
  🟠 Port  8080 | HTTP-alt     | MEDIUM   | Alternative web port

============================================================
📋 NETPROBE PRO REPORT
============================================================
🎯 Target:           example.com (93.184.216.34)
📅 Date:             2025-01-15 14:32:01
⏱️  Duration:         12.3 sec
🔍 Ports scanned:    1050
🚪 Open ports:       4

📊 RISK BREAKDOWN:
  🔴 CRITICAL: 1
  🟠 HIGH:     0
  🟡 MEDIUM:   2
  🟢 LOW:      1

⚡ OVERALL RISK LEVEL: CRITICAL

💡 RECOMMENDATIONS:
  🗄️  Database (MySQL) exposed to the internet — CLOSE immediately
  🔀 Both HTTP and HTTPS are open — redirect all traffic to HTTPS
============================================================

💾 JSON report saved: report_example.com_20250115_143201.json
💾 CSV report saved:  report_example.com_20250115_143201.csv
```

---

## Risk levels explained

| Level | Color | Meaning |
|-------|-------|---------|
| CRITICAL | 🔴 | Close this immediately — actively exploited in the wild |
| HIGH | 🟠 | Significant risk, should be addressed soon |
| MEDIUM | 🟡 | Worth reviewing, depends on your use case |
| LOW | 🟢 | Generally safe, just be aware |

---

## Ports covered

NetProbe Pro has a built-in database of 20+ well-known dangerous ports including:

| Port | Service | Risk |
|------|---------|------|
| 23 | Telnet | CRITICAL — no encryption at all |
| 445 | SMB | CRITICAL — exploited by WannaCry and others |
| 3306 | MySQL | CRITICAL — database open to the internet |
| 3389 | RDP | CRITICAL — remote desktop, frequent attack target |
| 6379 | Redis | CRITICAL — often runs without a password |
| 27017 | MongoDB | CRITICAL — often runs without a password |
| 21 | FTP | HIGH — transfers files without encryption |
| 5900 | VNC | HIGH — remote screen access |
| 80 | HTTP | MEDIUM — unencrypted web traffic |
| 443 | HTTPS | LOW — encrypted, generally OK |

---

## Output files

After every scan, two files are saved automatically:

**JSON** — full machine-readable report, good for integrating with other tools:
```json
{
  "target": "example.com",
  "ip": "93.184.216.34",
  "scan_date": "2025-01-15 14:32:01",
  "duration_seconds": 12.3,
  "open_ports": [...],
  "overall_risk": "CRITICAL",
  "recommendations": [...]
}
```

**CSV** — open in Excel or Google Sheets, good for client reports.

---

## Use cases

**For freelancers** — run a scan, send the CSV to your client, charge $30–100 for a basic security audit. The output is already written in plain language your client can understand.

**For developers** — run after every deployment to make sure no unexpected ports got exposed.

**For students** — practice port scanning in your lab without needing to learn complex tools like Nmap first.

**For small businesses** — quick check of your VPS or web server before going live.

---

## Legal notice

Only scan systems you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your jurisdiction. The author is not responsible for misuse.

---

## Roadmap

- [ ] GUI interface (Tkinter)
- [ ] PDF report export
- [ ] Service version detection
- [ ] CVE lookup for detected services
- [ ] Scheduled scans with email alerts

---

## License

MIT — free to use, modify, and sell.

---

## Author

Built by [Your Name] · [your@email.com] · [linkedin.com/in/yourprofile]
