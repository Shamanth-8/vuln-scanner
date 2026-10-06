# 🔍 Automated Vulnerability Scanner

> **Portfolio angle:** Automated vulnerability discovery pipeline reducing manual recon time by 4+ hours per assessment.

---

## What This Project Is

A production-grade Python tool that wraps Nmap's NSE scripting engine to automate vulnerability discovery, CVSS scoring, and report generation — the same workflow used by professional penetration testers.

**The problem it solves:** Manual recon (running individual nmap commands, manually scoring findings, copying results into Word) takes 4–6 hours. This pipeline does it in minutes and produces a client-ready HTML/PDF report automatically.

---

## Cybersecurity Concepts You Will Learn

### Port Scanning
Probing TCP/UDP ports on a target to discover what services are running. Every open port is a potential attack vector. Understanding which ports are "normal" for a system vs. unexpectedly open is the first skill in any pentest.

```
Port 22 open  → SSH service → possible brute force
Port 3306 open externally → MySQL exposed to internet → critical risk
```

### NSE — Nmap Scripting Engine
Lua scripts bundled with nmap that go beyond port discovery. NSE scripts can:
- Detect specific CVEs (e.g., EternalBlue / MS17-010)
- Test for weak/default credentials
- Check SSL/TLS misconfiguration
- Find SQL injection entry points

This project uses ~25 curated NSE scripts organised by category.

### CVSS — Common Vulnerability Scoring System
The industry standard for rating vulnerability severity (0.0–10.0):
| Score     | Severity | Meaning |
|-----------|----------|---------|
| 9.0–10.0  | Critical | Immediate exploitation likely, full system compromise possible |
| 7.0–8.9   | High     | Serious impact, exploitation is straightforward |
| 4.0–6.9   | Medium   | Requires specific conditions but still dangerous |
| 0.1–3.9   | Low      | Minimal impact, difficult to exploit |
| 0.0       | Info     | Informational only |

### Banner Grabbing
Reading a service's self-identification string (e.g., `Apache/2.4.41 (Ubuntu)`) to determine the exact software version. Combined with CVE databases, this reveals whether the installed version has known exploits.

### Remediation
Every finding in this scanner includes a remediation step — what to fix and how. This is the "AppSec mindset": not just finding problems but knowing how to fix them.

---

## Architecture

```
main.py (CLI)
    │
    ├── scanner/core.py      ← VulnerabilityScanner
    │       │
    │       ├── nmap/NSE     ← actual scanning
    │       └── parse XML    ← ScanResult + Vulnerability objects
    │
    ├── scanner/reporter.py  ← ReportGenerator
    │       │
    │       ├── Jinja2       ← HTML template rendering
    │       └── WeasyPrint   ← HTML → PDF conversion
    │
    └── scanner/notifier.py  ← SlackNotifier
            │
            └── Slack Webhook → Block Kit alert
```

### Why These Libraries?

| Library | Why |
|---------|-----|
| `python-nmap` | Official Python wrapper for nmap. Parses XML output so we work with dicts not raw strings |
| `Jinja2` | Separates report logic from HTML. Same engine used by Flask/Ansible. Industry standard |
| `weasyprint` | HTML→PDF without headless Chrome. Lightweight, no browser dependency |
| `pytest` | Standard Python test framework. Used in every professional Python project |

---

## File Structure

```
vuln-scanner/
├── main.py                         # CLI entry point
├── requirements.txt
├── scanner/
│   ├── __init__.py
│   ├── core.py                     # Scanner engine: nmap wrapper + data models
│   ├── reporter.py                 # HTML/PDF report generation
│   └── notifier.py                 # Slack alerting
├── templates/
│   └── report.html.j2              # Jinja2 HTML report template
├── reports/                        # Generated reports (gitignored)
├── tests/
│   └── test_scanner.py             # Pytest test suite
└── .github/
    └── workflows/
        └── weekly-scan.yml         # CI/CD pipeline
```

---

## Setup

```bash
# Install system dependency
sudo apt-get install nmap       # Ubuntu/Debian
brew install nmap               # macOS

# Install Python dependencies
cd vuln-scanner
pip install -r requirements.txt
```

---

## Usage

```bash
# Quick scan of a single host
python main.py --target 192.168.1.1

# Full port scan with PDF output
python main.py --target 10.0.0.1 --ports 1-65535 --pdf

# Scan and send findings to Slack
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
python main.py --target 192.168.1.1 --slack

# Scan nmap's own test server (legal, always available)
python main.py --target scanme.nmap.org --ports 1-1000

# Dry-run: preview Slack payload without sending
python main.py --target 192.168.1.1 --slack --dry-run
```

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | required | IP, hostname, or CIDR (e.g. `192.168.0.0/24`) |
| `--ports` | `1-1024` | Port range |
| `--timing` | `4` | Nmap timing T0–T5. T4=fast, T1=sneaky |
| `--pdf` | off | Generate PDF report (requires weasyprint) |
| `--slack` | off | Post summary to Slack |
| `--sudo` | off | Enable SYN (stealth) scan — needs root |
| `--output` | `reports/` | Output directory |

---

## NSE Scripts Used

### Web Vulnerability Checks
| Script | What it detects | CVSS |
|--------|----------------|------|
| `http-sql-injection` | SQL injection entry points | 9.8 Critical |
| `http-shellshock` | Shellshock in CGI scripts | 10.0 Critical |
| `http-csrf` | Cross-Site Request Forgery | 8.8 High |
| `http-stored-xss` | Stored Cross-Site Scripting | 8.8 High |
| `http-reflected-xss` | Reflected XSS | 6.1 Medium |
| `http-put` | HTTP PUT enabled (file upload = RCE) | 9.8 Critical |

### SSL/TLS Checks
| Script | What it detects | CVSS |
|--------|----------------|------|
| `ssl-heartbleed` | Heartbleed (CVE-2014-0160) | 7.5 High |
| `ssl-poodle` | POODLE attack on SSLv3 | 3.4 Low |
| `ssl-dh-params` | Weak Diffie-Hellman parameters | 7.4 High |
| `sslv2` | SSLv2 enabled (deprecated) | 7.4 High |

### Credential Checks
| Script | What it detects | CVSS |
|--------|----------------|------|
| `ssh-brute` | Weak SSH passwords | 9.8 Critical |
| `ftp-anon` | Anonymous FTP login | 7.5 High |
| `mysql-empty-password` | MySQL root with no password | 9.8 Critical |

### Windows/SMB Checks
| Script | What it detects | CVSS |
|--------|----------------|------|
| `smb-vuln-ms17-010` | EternalBlue (WannaCry vector) | 9.8 Critical |
| `smb-vuln-ms08-067` | Conficker worm vector | 10.0 Critical |

---

## CI/CD Pipeline

The `.github/workflows/weekly-scan.yml` runs every Monday at 02:00 UTC:

```
Schedule trigger
    → Install nmap + Python deps
    → Run scanner against SCAN_TARGET secret
    → Upload HTML/PDF reports as GitHub Artifacts (90-day retention)
    → POST summary to Slack
    → Fail the job if critical findings are found (security gate)
```

### Required GitHub Secrets
| Secret | Value |
|--------|-------|
| `SLACK_WEBHOOK_URL` | From Slack → Apps → Incoming Webhooks |
| `SCAN_TARGET` | Your test VM/lab IP |
| `REPORT_BASE_URL` | Optional: URL where you host reports |

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=scanner --cov-report=html

# Run a specific test class
pytest tests/test_scanner.py::TestCvssToSeverity -v
```

Tests cover:
- CVSS scoring edge cases
- Severity count accuracy
- CVE extraction from NSE output
- HTML/PDF report generation
- Slack payload structure
- Risk score tier classification

---

## Exit Codes

| Code | Meaning | Use in CI |
|------|---------|-----------|
| `0` | Clean scan, no high/critical | Pipeline passes |
| `1` | High severity findings | Warning |
| `2` | Critical findings | Pipeline fails, alerts fire |

This lets you gate deployments: if a weekly scan of your staging environment returns exit code 2, the pipeline blocks until the issue is fixed.

---

## Key Design Decisions

**Why nmap over alternatives like OpenVAS?**
Nmap is universally available, has no licensing issues, and NSE scripts cover 95% of what a first-pass recon scan needs. OpenVAS is better for deep authenticated scanning but is heavyweight for a portfolio project.

**Why WeasyPrint over headless Chrome?**
WeasyPrint is a pure-Python HTML→PDF converter with no browser dependency. Perfect for CI environments where installing Chrome is painful.

**Why python-nmap over subprocess?**
python-nmap parses nmap's XML output format, giving us structured dicts. Raw subprocess calls would require us to parse text output, which is fragile.

**Why Jinja2 templates instead of f-strings?**
Separation of concerns. The scanner produces data; the template produces presentation. Changing the report layout never requires touching scanner logic.

**Why exit code 2 for criticals?**
CI/CD security gates rely on exit codes. Returning a non-zero code on critical findings means your pipeline can block deployments, alert on-call engineers, and create JIRA tickets automatically.
