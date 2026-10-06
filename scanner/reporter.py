"""
reporter.py — Generates HTML and PDF vulnerability reports.

WHY JINJA2:
    Jinja2 lets us separate data from presentation. The scanner produces a
    ScanResult dict; Jinja2 renders it into a professional HTML report.
    WeasyPrint then converts that HTML → PDF without needing headless Chrome.

CONCEPTS EXPLAINED:
    - CVSS v3.1 base score: standardised 0–10 metric for vulnerability severity.
      Attackers, defenders, and recruiters all speak this language.
    - Remediation steps: what to fix and how. Showing these demonstrates that
      you understand both the attack AND the defence (AppSec mindset).
    - Report structure mirrors real-world pentest deliverables:
        Executive Summary → Scope → Findings → Remediation
"""

import os
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Union

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

# Directory containing Jinja2 templates
TEMPLATE_DIR = Path(__file__).parent.parent / "templates"

# Severity → Bootstrap badge colour (used in the HTML template)
SEVERITY_BADGE: dict[str, str] = {
    "Critical": "danger",
    "High":     "warning",
    "Medium":   "secondary",
    "Low":      "success",
    "Info":     "info",
}

# Severity → sort order (lower = more severe)
SEVERITY_ORDER: dict[str, int] = {
    "Critical": 0,
    "High":     1,
    "Medium":   2,
    "Low":      3,
    "Info":     4,
}


class ReportGenerator:
    """
    Renders ScanResult data into HTML and (optionally) PDF reports.

    The HTML template uses Bootstrap 5 for a clean, professional look that
    you can screenshot for a portfolio.

    Usage:
        gen = ReportGenerator(scan_result_dict)
        html_path = gen.render_html("reports/scan_2024.html")
        pdf_path  = gen.render_pdf("reports/scan_2024.pdf")
    """

    def __init__(self, scan_result: dict):
        self.result = scan_result
        self._env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        # Make severity helpers available inside templates
        self._env.globals["SEVERITY_BADGE"]  = SEVERITY_BADGE
        self._env.globals["SEVERITY_ORDER"]  = SEVERITY_ORDER
        self._env.filters["badge_class"]     = lambda s: SEVERITY_BADGE.get(s, "secondary")
        self._env.filters["severity_order"]  = lambda s: SEVERITY_ORDER.get(s, 99)

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def render_html(self, output_path: str) -> str:
        """Render to HTML and write to disk. Returns the absolute path."""
        template = self._env.get_template("report.html.j2")
        context  = self._build_context()
        html     = template.render(**context)

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html)

        logger.info(f"HTML report written to {output_path}")
        return os.path.abspath(output_path)

    def render_pdf(self, output_path: str) -> str:
        """
        Render to PDF via WeasyPrint.
        WeasyPrint converts the HTML report to PDF without a browser.
        Install: pip install weasyprint
        """
        try:
            from weasyprint import HTML as WeasyHTML  # type: ignore
        except ImportError:
            logger.warning(
                "weasyprint not installed — skipping PDF generation. "
                "Run: pip install weasyprint"
            )
            return ""

        # First produce an HTML string, then convert
        template = self._env.get_template("report.html.j2")
        context  = self._build_context()
        html_str = template.render(**context)

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        WeasyHTML(string=html_str).write_pdf(output_path)

        logger.info(f"PDF report written to {output_path}")
        return os.path.abspath(output_path)

    def render_json_summary(self, output_path: str) -> str:
        """Write a machine-readable JSON summary (useful for CI/CD and Slack)."""
        summary = {
            "target":         self.result.get("target"),
            "scan_start":     self.result.get("scan_start"),
            "scan_end":       self.result.get("scan_end"),
            "hostname":       self.result.get("hostname"),
            "state":          self.result.get("state"),
            "total_findings": len(self.result.get("vulnerabilities", [])),
            "critical":       self.result.get("critical_count", 0),
            "high":           self.result.get("high_count", 0),
            "medium":         self.result.get("medium_count", 0),
            "low":            self.result.get("low_count", 0),
            "top_findings":   self._top_findings(3),
        }

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as fh:
            json.dump(summary, fh, indent=2)

        logger.info(f"JSON summary written to {output_path}")
        return os.path.abspath(output_path)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_context(self) -> dict:
        """Flatten the scan result into template-friendly variables."""
        vulns = self.result.get("vulnerabilities", [])

        return {
            "target":          self.result.get("target", "Unknown"),
            "hostname":        self.result.get("hostname", "Unknown"),
            "scan_start":      self.result.get("scan_start", ""),
            "scan_end":        self.result.get("scan_end", ""),
            "state":           self.result.get("state", "unknown"),
            "os_guess":        self.result.get("os_guess", "Unknown"),
            "open_ports":      self.result.get("open_ports", []),
            "vulnerabilities": vulns,
            "critical_count":  self.result.get("critical_count", 0),
            "high_count":      self.result.get("high_count", 0),
            "medium_count":    self.result.get("medium_count", 0),
            "low_count":       self.result.get("low_count", 0),
            "total_count":     len(vulns),
            "generated_at":    datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            "risk_score":      self._calculate_risk_score(vulns),
        }

    @staticmethod
    def _calculate_risk_score(vulns: list) -> str:
        """
        Weighted risk score: reflects combined impact across all findings.
        Weight: Critical=10, High=7, Medium=4, Low=1
        Normalised to 0–100 scale for the executive summary gauge.
        """
        weights = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Info": 0}
        raw = sum(weights.get(v.get("severity", "Info"), 0) for v in vulns)
        # Clamp to 100
        normalised = min(raw, 100)
        if normalised >= 75:
            return f"{normalised} — CRITICAL RISK"
        elif normalised >= 50:
            return f"{normalised} — HIGH RISK"
        elif normalised >= 25:
            return f"{normalised} — MEDIUM RISK"
        return f"{normalised} — LOW RISK"

    def _top_findings(self, n: int = 3) -> list[dict]:
        """Return the n most severe findings for the Slack notification."""
        vulns = self.result.get("vulnerabilities", [])
        sorted_vulns = sorted(
            vulns,
            key=lambda v: (SEVERITY_ORDER.get(v.get("severity", "Info"), 99), -v.get("cvss_score", 0)),
        )
        return [
            {
                "port":      v.get("port"),
                "service":   v.get("service"),
                "script_id": v.get("script_id"),
                "severity":  v.get("severity"),
                "cvss":      v.get("cvss_score"),
                "cve":       v.get("cve"),
            }
            for v in sorted_vulns[:n]
        ]
