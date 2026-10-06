"""
core.py — Heart of the vulnerability scanner.

WHY THIS EXISTS:
    Nmap is the industry-standard port/service scanner. python-nmap wraps the
    nmap CLI so we can drive it programmatically, parse XML output, and feed
    results into our reporting pipeline.

CONCEPTS EXPLAINED:
    - Port scanning: probing TCP/UDP ports to discover which services are
      running on a target host. Open ports = attack surface.
    - NSE (Nmap Scripting Engine): Lua scripts bundled with nmap that go
      beyond port discovery — they can detect CVEs, weak credentials,
      SSL misconfigurations, etc.
    - CVSS (Common Vulnerability Scoring System): 0–10 float that rates
      vulnerability severity. ≥9.0 = Critical, 7–8.9 = High, etc.
    - Banner grabbing: reading the service's self-identification string to
      infer the exact software version, which maps to known CVEs.
"""

import nmap
import json
import logging
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field, asdict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Vulnerability:
    """
    One discrete finding. Mirrors the structure of a CVE record so that
    the reporting layer can render CVSS scores and remediation advice.
    """
    port: int
    protocol: str          # "tcp" or "udp"
    service: str           # e.g. "http", "ssh", "ftp"
    version: str           # banner-grabbed version string
    script_id: str         # NSE script that fired
    output: str            # raw NSE output
    severity: str          # Critical / High / Medium / Low / Info
    cvss_score: float      # 0.0–10.0
    cve: Optional[str]     # "CVE-YYYY-NNNNN" if known
    remediation: str       # human-readable fix


@dataclass
class ScanResult:
    """
    Aggregated results for one target host.
    Everything the report template needs lives here.
    """
    target: str
    scan_start: str
    scan_end: str
    hostname: str
    state: str                          # "up" or "down"
    os_guess: str
    open_ports: list[dict] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    # Derived counts used by the HTML/PDF template
    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "Critical")

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "High")

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "Medium")

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "Low")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["critical_count"] = self.critical_count
        d["high_count"] = self.high_count
        d["medium_count"] = self.medium_count
        d["low_count"] = self.low_count
        return d


# ---------------------------------------------------------------------------
# CVSS / severity helpers
# ---------------------------------------------------------------------------

# NSE scripts we run and the baseline CVSS we assign when the script fires.
# In a production scanner you'd query the NVD API for real scores.
NSE_SEVERITY_MAP: dict[str, tuple[float, str]] = {
    # Web application checks
    "http-sql-injection":          (9.8, "Critical"),
    "http-shellshock":             (10.0, "Critical"),
    "http-csrf":                   (8.8, "High"),
    "http-dombased-xss":           (6.1, "Medium"),
    "http-stored-xss":             (8.8, "High"),
    "http-reflected-xss":          (6.1, "Medium"),
    "http-open-redirect":          (6.1, "Medium"),
    "http-default-accounts":       (9.8, "Critical"),
    "http-auth-finder":            (5.3, "Medium"),
    "http-methods":                (5.3, "Medium"),
    "http-put":                    (9.8, "Critical"),  # file upload = RCE
    "http-webdav-scan":            (7.5, "High"),
    # SSL / TLS checks
    "ssl-heartbleed":              (7.5, "High"),
    "ssl-poodle":                  (3.4, "Low"),
    "ssl-dh-params":               (7.4, "High"),
    "ssl-ccs-injection":           (7.4, "High"),
    "ssl-cert":                    (0.0, "Info"),      # informational only
    "sslv2":                       (7.4, "High"),
    "tls-ticketbleed":             (7.5, "High"),
    # Credential / auth checks
    "ssh-brute":                   (9.8, "Critical"),
    "ftp-brute":                   (9.8, "Critical"),
    "ftp-anon":                    (7.5, "High"),
    "smtp-open-relay":             (7.5, "High"),
    "snmp-brute":                  (9.8, "Critical"),
    "mysql-brute":                 (9.8, "Critical"),
    "mysql-empty-password":        (9.8, "Critical"),
    # SMB / Windows checks
    "smb-vuln-ms17-010":           (9.8, "Critical"),  # EternalBlue
    "smb-vuln-ms08-067":           (10.0, "Critical"),
    "smb2-security-mode":          (5.3, "Medium"),
}

REMEDIATION_MAP: dict[str, str] = {
    "http-sql-injection":     "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
    "http-shellshock":        "Update bash to ≥4.3. Restrict CGI execution. Apply vendor patches.",
    "http-csrf":              "Implement synchronizer CSRF tokens (Flask-WTF / Django CSRF middleware). Validate Origin header.",
    "http-dombased-xss":      "Sanitize DOM writes; use textContent instead of innerHTML. Apply strict CSP.",
    "http-stored-xss":        "Output-encode all user-supplied data. Use Content-Security-Policy headers.",
    "http-reflected-xss":     "HTML-encode all reflected parameters. Set X-XSS-Protection and CSP headers.",
    "http-open-redirect":     "Whitelist allowed redirect destinations. Never redirect to user-supplied URLs.",
    "http-default-accounts":  "Change all default credentials immediately. Disable demo/admin accounts before production.",
    "http-put":               "Disable HTTP PUT/DELETE on the web server unless explicitly required.",
    "ssl-heartbleed":         "Patch OpenSSL to ≥1.0.1g. Revoke and reissue TLS certificates.",
    "ssl-poodle":             "Disable SSLv3. Prefer TLS 1.2+.",
    "ssl-dh-params":          "Use DH parameters ≥2048 bits. Prefer ECDHE for forward secrecy.",
    "sslv2":                  "Disable SSLv2 on the server. Use TLS 1.2 or TLS 1.3.",
    "ssh-brute":              "Disable password authentication; use SSH keys only. Implement fail2ban.",
    "ftp-anon":               "Disable anonymous FTP logins. Use SFTP instead.",
    "smtp-open-relay":        "Require authentication for mail relay. Add SPF/DKIM/DMARC records.",
    "smb-vuln-ms17-010":      "Apply Microsoft MS17-010 patch (KB4012212). Disable SMBv1.",
    "mysql-empty-password":   "Set strong passwords for all MySQL accounts. Run mysql_secure_installation.",
}


def cvss_to_severity(score: float) -> str:
    """Map a CVSS 3.x base score to a human-readable severity label."""
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0.0:
        return "Low"
    return "Info"


# ---------------------------------------------------------------------------
# Main scanner class
# ---------------------------------------------------------------------------

class VulnerabilityScanner:
    """
    Drives nmap with a curated set of NSE scripts and parses the output into
    structured Vulnerability objects.

    Usage:
        scanner = VulnerabilityScanner(target="192.168.1.1", ports="1-1024")
        result = scanner.scan()
        print(result.to_dict())
    """

    # NSE script categories to run.  Grouped for clarity:
    #   vuln   — exploits / CVE checks
    #   auth   — default/weak credential checks
    #   ssl    — TLS/SSL misconfiguration
    #   http-* — web-specific scripts
    DEFAULT_SCRIPTS = (
        "vuln,"
        "auth,"
        "ssl-heartbleed,ssl-poodle,ssl-dh-params,ssl-ccs-injection,ssl-cert,"
        "sslv2,tls-ticketbleed,"
        "http-sql-injection,http-shellshock,http-csrf,"
        "http-dombased-xss,http-stored-xss,http-reflected-xss,"
        "http-open-redirect,http-default-accounts,http-auth-finder,"
        "http-methods,http-put,http-webdav-scan,"
        "ftp-anon,smtp-open-relay,smb-vuln-ms17-010,smb2-security-mode"
    )

    def __init__(
        self,
        target: str,
        ports: str = "1-1024",
        timing: int = 4,
        scripts: Optional[str] = None,
        sudo: bool = False,
        os_detection: bool = False,
    ):
        """
        Args:
            target:       IP, hostname, or CIDR range (e.g. "192.168.1.0/24")
            ports:        nmap port expression  (e.g. "80,443,22" or "1-65535")
            timing:       nmap -T flag 0–5.  T4 = aggressive (fast lab use)
            scripts:      comma-separated NSE scripts; defaults to DEFAULT_SCRIPTS
            sudo:         run nmap with sudo (enables SYN scan on Linux)
            os_detection: enable OS fingerprinting (-O). Requires root/sudo.
                          Disabled by default so the scanner works without root.
        """
        self.target = target
        self.ports = ports
        self.timing = timing
        self.scripts = scripts or self.DEFAULT_SCRIPTS
        self.sudo = sudo
        self.os_detection = os_detection
        self._nm = nmap.PortScanner()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def scan(self) -> ScanResult:
        """
        Execute the full scan and return a ScanResult.

        What happens:
          1. nmap SYN (-sS) or TCP-connect (-sT) scan across `ports`
          2. Version detection (-sV) for banner grabbing
          3. OS fingerprinting (-O)
          4. NSE script execution (--script)
          5. Parse XML output → Vulnerability objects
        """
        start_time = datetime.utcnow().isoformat()
        logger.info(f"Starting scan of {self.target} on ports {self.ports}")

        # Build nmap arguments.
        # -sV  : probe open ports to determine service/version info
        # -O   : OS detection (requires root — only added when os_detection=True)
        # -sS  : TCP SYN (stealth) scan — requires root; falls back to -sT
        # -T{n}: timing template (T4 = fast, good for labs)
        scan_flag = "-sS" if self.sudo else "-sT"
        os_flag   = "-O" if self.os_detection else ""
        args = (
            f"{scan_flag} -sV {os_flag} --script {self.scripts} "
            f"-T{self.timing} -p {self.ports}"
        ).strip()

        try:
            self._nm.scan(hosts=self.target, arguments=args, sudo=self.sudo)
        except nmap.PortScannerError as exc:
            logger.error(f"nmap error: {exc}")
            raise

        end_time = datetime.utcnow().isoformat()
        result = self._parse_results(start_time, end_time)
        logger.info(
            f"Scan complete. Found {len(result.vulnerabilities)} findings "
            f"({result.critical_count} critical, {result.high_count} high)"
        )
        return result

    def scan_to_json(self, output_path: str) -> ScanResult:
        """Convenience: scan and also write raw JSON for archiving."""
        result = self.scan()
        with open(output_path, "w") as fh:
            json.dump(result.to_dict(), fh, indent=2)
        logger.info(f"Raw JSON saved to {output_path}")
        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_results(self, start_time: str, end_time: str) -> ScanResult:
        vulnerabilities: list[Vulnerability] = []
        open_ports: list[dict] = []
        hostname = ""
        state = "down"
        os_guess = "Unknown"

        for host in self._nm.all_hosts():
            host_data = self._nm[host]
            state = host_data.state()

            # Hostname resolution
            hostnames = host_data.hostnames()
            hostname = hostnames[0]["name"] if hostnames else host

            # OS fingerprinting
            if "osmatch" in host_data and host_data["osmatch"]:
                os_guess = host_data["osmatch"][0]["name"]

            # Walk each protocol (tcp / udp)
            for proto in host_data.all_protocols():
                ports = sorted(host_data[proto].keys())
                for port in ports:
                    port_info = host_data[proto][port]
                    if port_info["state"] != "open":
                        continue

                    service = port_info.get("name", "unknown")
                    version = (
                        f"{port_info.get('product', '')} "
                        f"{port_info.get('version', '')} "
                        f"{port_info.get('extrainfo', '')}".strip()
                        or "unknown"
                    )

                    open_ports.append(
                        {
                            "port": port,
                            "protocol": proto,
                            "state": port_info["state"],
                            "service": service,
                            "version": version,
                        }
                    )

                    # Check each NSE script result on this port
                    script_results = port_info.get("script", {})
                    for script_id, output in script_results.items():
                        # Skip scripts that returned nothing interesting
                        if not output or "ERROR" in output.upper():
                            continue

                        cvss, severity = NSE_SEVERITY_MAP.get(
                            script_id, (2.0, "Low")
                        )
                        remediation = REMEDIATION_MAP.get(
                            script_id,
                            "Review the finding, apply vendor patches, and follow hardening guides.",
                        )

                        vuln = Vulnerability(
                            port=port,
                            protocol=proto,
                            service=service,
                            version=version,
                            script_id=script_id,
                            output=output[:2000],  # cap size
                            severity=severity,
                            cvss_score=cvss,
                            cve=self._extract_cve(output),
                            remediation=remediation,
                        )
                        vulnerabilities.append(vuln)

        # Sort by CVSS descending so critical issues appear first
        vulnerabilities.sort(key=lambda v: v.cvss_score, reverse=True)

        return ScanResult(
            target=self.target,
            scan_start=start_time,
            scan_end=end_time,
            hostname=hostname,
            state=state,
            os_guess=os_guess,
            open_ports=open_ports,
            vulnerabilities=vulnerabilities,
        )

    @staticmethod
    def _extract_cve(text: str) -> Optional[str]:
        """
        Pull the first CVE identifier out of NSE script output.
        NSE scripts often print 'CVE: CVE-YYYY-NNNNN' in their output.
        """
        import re
        match = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
        return match.group(0).upper() if match else None
