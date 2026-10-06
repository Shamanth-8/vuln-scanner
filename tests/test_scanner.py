"""
tests/test_scanner.py — Unit tests for the vulnerability scanner.

WHY TESTS FOR A SECURITY TOOL:
    Security tools that produce false positives or miss real issues are worse
    than no tools. Tests ensure our severity mapping, CVSS scoring, CVE
    extraction, and report generation all behave correctly.

    We mock nmap calls so tests run in any CI environment (no root, no network).

TESTING CONCEPTS:
    - Mocking: replacing real dependencies (nmap) with controlled fakes so
      tests are fast, isolated, and reproducible.
    - Parametrize: run the same test logic against multiple input sets.
    - Fixtures: reusable setup code (sample scan data).
"""

import json
import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

# Make sure we can import from parent directory
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.core import (
    VulnerabilityScanner,
    ScanResult,
    Vulnerability,
    cvss_to_severity,
    NSE_SEVERITY_MAP,
)
from scanner.reporter import ReportGenerator
from scanner.notifier import SlackNotifier


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def sample_vuln() -> Vulnerability:
    """A single sample vulnerability for testing."""
    return Vulnerability(
        port=80,
        protocol="tcp",
        service="http",
        version="Apache httpd 2.4.41",
        script_id="http-sql-injection",
        output="Possible sqli for queries: ?id=1'",
        severity="Critical",
        cvss_score=9.8,
        cve="CVE-2021-41773",
        remediation="Use parameterized queries.",
    )


@pytest.fixture
def sample_scan_result(sample_vuln) -> ScanResult:
    """A complete ScanResult with mixed severities."""
    return ScanResult(
        target="192.168.1.1",
        scan_start="2024-01-01T00:00:00",
        scan_end="2024-01-01T00:05:00",
        hostname="testhost.local",
        state="up",
        os_guess="Linux 4.x",
        open_ports=[
            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.2"},
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Apache 2.4.41"},
        ],
        vulnerabilities=[
            sample_vuln,
            Vulnerability(
                port=22, protocol="tcp", service="ssh", version="OpenSSH 8.2",
                script_id="ssh-brute", output="Found credentials: admin/admin",
                severity="Critical", cvss_score=9.8, cve=None,
                remediation="Disable password auth.",
            ),
            Vulnerability(
                port=443, protocol="tcp", service="https", version="nginx",
                script_id="ssl-heartbleed", output="VULNERABLE",
                severity="High", cvss_score=7.5, cve="CVE-2014-0160",
                remediation="Patch OpenSSL.",
            ),
            Vulnerability(
                port=80, protocol="tcp", service="http", version="Apache",
                script_id="http-dombased-xss", output="Found XSS",
                severity="Medium", cvss_score=6.1, cve=None,
                remediation="Sanitize DOM writes.",
            ),
        ],
    )


# ===========================================================================
# Tests: cvss_to_severity
# ===========================================================================

class TestCvssToSeverity:
    """CVSS score → severity label mapping."""

    @pytest.mark.parametrize("score, expected", [
        (10.0, "Critical"),
        (9.0,  "Critical"),
        (8.9,  "High"),
        (7.0,  "High"),
        (6.9,  "Medium"),
        (4.0,  "Medium"),
        (3.9,  "Low"),
        (0.1,  "Low"),
        (0.0,  "Info"),
    ])
    def test_score_to_label(self, score: float, expected: str):
        assert cvss_to_severity(score) == expected

    def test_all_nse_scripts_have_severity(self):
        """Every NSE script in our map should produce a valid severity."""
        valid = {"Critical", "High", "Medium", "Low", "Info"}
        for script, (score, severity) in NSE_SEVERITY_MAP.items():
            assert severity in valid, f"{script} has invalid severity: {severity}"
            assert 0.0 <= score <= 10.0, f"{script} has invalid CVSS: {score}"


# ===========================================================================
# Tests: ScanResult
# ===========================================================================

class TestScanResult:
    def test_severity_counts(self, sample_scan_result):
        r = sample_scan_result
        assert r.critical_count == 2
        assert r.high_count == 1
        assert r.medium_count == 1
        assert r.low_count == 0

    def test_to_dict_contains_counts(self, sample_scan_result):
        d = sample_scan_result.to_dict()
        assert d["critical_count"] == 2
        assert d["high_count"] == 1
        assert d["target"] == "192.168.1.1"

    def test_to_dict_serializable(self, sample_scan_result):
        """to_dict() output must be JSON-serializable."""
        d = sample_scan_result.to_dict()
        serialized = json.dumps(d)
        assert isinstance(serialized, str)

    def test_vulnerabilities_sorted_by_cvss(self, sample_scan_result):
        """Vulnerabilities must be sorted highest CVSS first."""
        scores = [v.cvss_score for v in sample_scan_result.vulnerabilities]
        assert scores == sorted(scores, reverse=True)


# ===========================================================================
# Tests: VulnerabilityScanner._extract_cve
# ===========================================================================

class TestExtractCve:
    @pytest.mark.parametrize("text, expected", [
        ("CVE: CVE-2021-41773",     "CVE-2021-41773"),
        ("cve-2014-0160",           "CVE-2014-0160"),      # case-insensitive
        ("VULNERABLE (see CVE-2017-0144)", "CVE-2017-0144"),
        ("No CVE mentioned here",   None),
        ("",                        None),
    ])
    def test_cve_extraction(self, text, expected):
        result = VulnerabilityScanner._extract_cve(text)
        assert result == expected


# ===========================================================================
# Tests: VulnerabilityScanner (mocked nmap)
# ===========================================================================

class TestVulnerabilityScanner:
    """
    We mock nmap.PortScanner so these tests run without root and without
    network access — safe for any CI environment.
    """

    def _make_mock_nm(self, host="192.168.1.1"):
        """Build a minimal nmap.PortScanner mock that returns one open port."""
        nm = MagicMock()
        nm.all_hosts.return_value = [host]
        host_data = MagicMock()
        host_data.state.return_value = "up"
        host_data.hostnames.return_value = [{"name": "testhost", "type": "PTR"}]
        host_data.__getitem__ = MagicMock(return_value={"osmatch": []})
        host_data.all_protocols.return_value = ["tcp"]
        host_data.__getitem__.return_value = {
            "osmatch": [{"name": "Linux 4.x", "accuracy": "90"}],
            "tcp": {
                80: {
                    "state": "open",
                    "name": "http",
                    "product": "Apache",
                    "version": "2.4.41",
                    "extrainfo": "",
                    "script": {
                        "http-sql-injection": "Possible sqli for ?id=1' CVE-2021-41773",
                    },
                }
            },
        }
        nm.__getitem__ = MagicMock(return_value=host_data)
        return nm

    @patch("scanner.core.nmap.PortScanner")
    def test_scan_returns_scan_result(self, MockScanner):
        nm_mock = MagicMock()
        nm_mock.scan.return_value = None

        # Set up host data
        host_data = {
            "osmatch": [{"name": "Linux", "accuracy": "90"}],
            "tcp": {
                80: {
                    "state": "open",
                    "name": "http",
                    "product": "Apache",
                    "version": "2.4.41",
                    "extrainfo": "",
                    "script": {
                        "http-sql-injection": "Possible sqli CVE-2021-41773",
                    },
                }
            },
        }
        nm_mock.all_hosts.return_value = ["192.168.1.1"]

        # Create a proper host mock
        host_mock = MagicMock()
        host_mock.state.return_value = "up"
        host_mock.hostnames.return_value = [{"name": "test.local", "type": "PTR"}]
        host_mock.all_protocols.return_value = ["tcp"]
        host_mock.__getitem__ = lambda self, key: host_data[key] if key in host_data else {}

        nm_mock.__getitem__ = lambda self, key: host_mock
        MockScanner.return_value = nm_mock

        scanner = VulnerabilityScanner(target="192.168.1.1")
        # Patch the internal _nm attribute directly
        scanner._nm = nm_mock
        result = scanner._parse_results("2024-01-01T00:00:00", "2024-01-01T00:05:00")

        assert isinstance(result, ScanResult)
        assert result.target == "192.168.1.1"

    def test_scanner_init(self):
        with patch("scanner.core.nmap.PortScanner"):
            s = VulnerabilityScanner(target="10.0.0.1", ports="80,443", timing=3)
            assert s.target == "10.0.0.1"
            assert s.ports == "80,443"
            assert s.timing == 3


# ===========================================================================
# Tests: ReportGenerator
# ===========================================================================

class TestReportGenerator:
    def test_render_html_creates_file(self, tmp_path, sample_scan_result):
        result_dict = sample_scan_result.to_dict()
        gen = ReportGenerator(result_dict)
        out = str(tmp_path / "report.html")
        path = gen.render_html(out)
        assert Path(path).exists()

    def test_html_contains_target(self, tmp_path, sample_scan_result):
        result_dict = sample_scan_result.to_dict()
        gen = ReportGenerator(result_dict)
        out = str(tmp_path / "report.html")
        gen.render_html(out)
        html = Path(out).read_text()
        assert "192.168.1.1" in html

    def test_html_contains_severity_badges(self, tmp_path, sample_scan_result):
        result_dict = sample_scan_result.to_dict()
        gen = ReportGenerator(result_dict)
        out = str(tmp_path / "report.html")
        gen.render_html(out)
        html = Path(out).read_text()
        assert "Critical" in html
        assert "CVE-2014-0160" in html

    def test_json_summary(self, tmp_path, sample_scan_result):
        result_dict = sample_scan_result.to_dict()
        gen = ReportGenerator(result_dict)
        out = str(tmp_path / "summary.json")
        gen.render_json_summary(out)
        data = json.loads(Path(out).read_text())
        assert data["critical"] == 2
        assert data["target"] == "192.168.1.1"
        assert len(data["top_findings"]) <= 3

    @pytest.mark.parametrize("vulns, expected_tier", [
        # Critical tier: ≥75  →  8 × Critical(weight=10) = 80  ✓
        ([{"severity": "Critical", "cvss_score": 9.8}] * 8, "CRITICAL RISK"),
        # High tier:     50–74 →  8 × High(weight=7)    = 56  ✓
        ([{"severity": "High",     "cvss_score": 8.0}] * 8, "HIGH RISK"),
        # Medium tier:   25–49 →  9 × Medium(weight=4)  = 36  ✓
        ([{"severity": "Medium",   "cvss_score": 5.0}] * 9, "MEDIUM RISK"),
        # Low tier:      <25   →  3 × Low(weight=1)     = 3   ✓
        ([{"severity": "Low",      "cvss_score": 2.0}] * 3, "LOW RISK"),
    ])
    def test_risk_score_tiers(self, vulns, expected_tier):
        score = ReportGenerator._calculate_risk_score(vulns)
        assert expected_tier in score


# ===========================================================================
# Tests: SlackNotifier
# ===========================================================================

class TestSlackNotifier:
    def test_dry_run_prints_payload(self, capsys, sample_scan_result):
        notifier = SlackNotifier(webhook_url="https://hooks.slack.com/test")
        result   = notifier.send_scan_summary(
            sample_scan_result.to_dict(), dry_run=True
        )
        assert result is True
        captured = capsys.readouterr()
        assert "vulnerability" in captured.out.lower() or "scan" in captured.out.lower()

    def test_no_webhook_returns_false(self, sample_scan_result):
        notifier = SlackNotifier(webhook_url=None)
        result   = notifier.send_scan_summary(sample_scan_result.to_dict())
        assert result is False

    def test_payload_has_correct_colour_for_critical(self, sample_scan_result):
        notifier = SlackNotifier(webhook_url="https://test")
        payload  = notifier._build_payload(sample_scan_result.to_dict(), "")
        # Critical findings → red attachment
        assert payload["attachments"][0]["color"] == "#FF0000"

    def test_payload_structure(self, sample_scan_result):
        notifier = SlackNotifier(webhook_url="https://test")
        payload  = notifier._build_payload(sample_scan_result.to_dict(), "https://example.com/report.html")
        assert "attachments" in payload
        blocks = payload["attachments"][0]["blocks"]
        assert any(b.get("type") == "header" for b in blocks)
