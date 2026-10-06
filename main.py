"""
main.py — CLI entry point for the vulnerability scanner.

Run:
    python main.py --target 192.168.1.1
    python main.py --target scanme.nmap.org --ports 1-65535 --output reports/
    python main.py --target 10.0.0.0/24 --pdf --slack

The scanner workflow:
    Target → nmap/NSE → ScanResult → HTML/PDF report → Slack alert
"""

import argparse
import sys
import logging
import os
from pathlib import Path
from datetime import datetime

# Allow running from project root
sys.path.insert(0, str(Path(__file__).parent))

from scanner.core import VulnerabilityScanner
from scanner.reporter import ReportGenerator
from scanner.notifier import SlackNotifier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Automated vulnerability scanner — Nmap/NSE + CVSS reporting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick scan of a single host
  python main.py --target 192.168.1.1

  # Full port scan with PDF output
  python main.py --target 10.0.0.1 --ports 1-65535 --pdf

  # Scan a subnet and send findings to Slack
  python main.py --target 192.168.0.0/24 --slack

  # Use nmap.org's deliberately open test host
  python main.py --target scanme.nmap.org --ports 1-1000
        """,
    )
    parser.add_argument("--target",  required=True,   help="IP, hostname, or CIDR range")
    parser.add_argument("--ports",   default="1-1024", help="Port range (default: 1-1024)")
    parser.add_argument("--timing",  default=4, type=int, choices=range(0, 6),
                        help="Nmap timing template T0–T5 (default: T4)")
    parser.add_argument("--scripts", default=None,
                        help="Custom NSE script list (comma-separated)")
    parser.add_argument("--output",  default="reports",
                        help="Directory to save reports (default: ./reports)")
    parser.add_argument("--pdf",     action="store_true",
                        help="Also generate a PDF report (requires weasyprint)")
    parser.add_argument("--slack",   action="store_true",
                        help="Post summary to Slack (requires SLACK_WEBHOOK_URL env var)")
    parser.add_argument("--sudo",    action="store_true",
                        help="Run nmap with sudo (enables SYN scan)")
    parser.add_argument("--os",      action="store_true",
                        help="Enable OS fingerprinting (-O). Requires root/sudo.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print Slack payload but do not POST")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    # ----------------------------------------------------------------
    # 1. Run the scan
    # ----------------------------------------------------------------
    logger.info(f"Target: {args.target}  Ports: {args.ports}  Timing: T{args.timing}")
    scanner = VulnerabilityScanner(
        target=args.target,
        ports=args.ports,
        timing=args.timing,
        scripts=args.scripts,
        sudo=args.sudo,
        os_detection=args.os,
    )

    try:
        result = scanner.scan()
    except Exception as exc:
        logger.error(f"Scan failed: {exc}")
        return 1

    # ----------------------------------------------------------------
    # 2. Generate reports
    # ----------------------------------------------------------------
    timestamp   = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_target = args.target.replace("/", "_").replace(".", "_")
    base_name   = f"scan_{safe_target}_{timestamp}"
    out_dir     = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    result_dict = result.to_dict()
    gen         = ReportGenerator(result_dict)

    # Always produce HTML + JSON
    html_path = gen.render_html(str(out_dir / f"{base_name}.html"))
    json_path = gen.render_json_summary(str(out_dir / f"{base_name}_summary.json"))
    pdf_path  = ""

    if args.pdf:
        pdf_path = gen.render_pdf(str(out_dir / f"{base_name}.pdf"))

    # ----------------------------------------------------------------
    # 3. Slack notification
    # ----------------------------------------------------------------
    if args.slack:
        notifier    = SlackNotifier()
        report_url  = os.environ.get("REPORT_BASE_URL", "")
        if report_url:
            report_url = f"{report_url}/{base_name}.html"
        notifier.send_scan_summary(
            result_dict,
            report_url=report_url,
            dry_run=args.dry_run,
        )

    # ----------------------------------------------------------------
    # 4. Print a brief summary to stdout (CI/CD can read this)
    # ----------------------------------------------------------------
    print("\n" + "=" * 60)
    print(f"  SCAN SUMMARY — {args.target}")
    print("=" * 60)
    print(f"  Host state : {result.state}")
    print(f"  Open ports : {len(result.open_ports)}")
    print(f"  Findings   : {len(result.vulnerabilities)}")
    print(f"    Critical : {result.critical_count}")
    print(f"    High     : {result.high_count}")
    print(f"    Medium   : {result.medium_count}")
    print(f"    Low      : {result.low_count}")
    print(f"\n  HTML report: {html_path}")
    print(f"  JSON summary: {json_path}")
    if pdf_path:
        print(f"  PDF report : {pdf_path}")
    print("=" * 60 + "\n")

    # Return non-zero exit code if critical findings — useful for CI gates
    if result.critical_count > 0:
        logger.warning("Critical vulnerabilities found — exiting with code 2")
        return 2
    if result.high_count > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
