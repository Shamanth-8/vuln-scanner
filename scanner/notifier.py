"""
notifier.py — Sends scan findings to Slack via Incoming Webhook.

WHY SLACK INTEGRATION:
    In a real SecOps environment, nobody reads email alerts. Slack/Teams
    channels with rich-formatted findings get actioned faster. This module
    demonstrates that you can wire up automated alerting (SecOps automation).

CONCEPTS:
    - Incoming Webhook: a Slack-generated URL you POST JSON payloads to.
      No OAuth, no bot token — lowest-friction alerting.
    - Block Kit: Slack's layout framework for rich messages (sections,
      context, dividers). Produces professional-looking alerts.
    - Severity colour coding: imitates how SOC dashboards colour-code alerts
      so analysts can triage at a glance.
"""

import json
import logging
import os
from urllib import request, error

logger = logging.getLogger(__name__)

# Map severity → Slack attachment colour hex
SEVERITY_COLOUR: dict[str, str] = {
    "Critical": "#FF0000",
    "High":     "#FF8C00",
    "Medium":   "#FFD700",
    "Low":      "#36a64f",
    "Info":     "#439FE0",
}


class SlackNotifier:
    """
    Sends a formatted vulnerability summary to a Slack channel.

    Set the webhook URL via the SLACK_WEBHOOK_URL environment variable
    (never hardcode it — that's a credential leak).

    Usage:
        notifier = SlackNotifier()
        notifier.send_scan_summary(scan_result_dict, report_url="https://...")
    """

    def __init__(self, webhook_url: str | None = None):
        self.webhook_url = webhook_url or os.environ.get("SLACK_WEBHOOK_URL")
        if not self.webhook_url:
            logger.warning(
                "SLACK_WEBHOOK_URL not set — Slack notifications disabled."
            )

    def send_scan_summary(
        self,
        result: dict,
        report_url: str = "",
        dry_run: bool = False,
    ) -> bool:
        """
        Post a Block Kit summary to Slack.

        Args:
            result:     scan result dict (from ScanResult.to_dict())
            report_url: link to the hosted HTML report
            dry_run:    if True, print payload instead of POSTing

        Returns:
            True on success, False on failure
        """
        if not self.webhook_url and not dry_run:
            logger.info("Skipping Slack notification (no webhook configured)")
            return False

        payload = self._build_payload(result, report_url)

        if dry_run:
            print(json.dumps(payload, indent=2))
            return True

        return self._post(payload)

    # ------------------------------------------------------------------
    # Payload builder
    # ------------------------------------------------------------------

    def _build_payload(self, result: dict, report_url: str) -> dict:
        target   = result.get("target", "Unknown")
        hostname = result.get("hostname", "")
        critical = result.get("critical_count", 0)
        high     = result.get("high_count", 0)
        medium   = result.get("medium_count", 0)
        low      = result.get("low_count", 0)
        total    = len(result.get("vulnerabilities", []))

        # Pick the worst severity for the attachment colour
        if critical > 0:
            colour = SEVERITY_COLOUR["Critical"]
        elif high > 0:
            colour = SEVERITY_COLOUR["High"]
        elif medium > 0:
            colour = SEVERITY_COLOUR["Medium"]
        else:
            colour = SEVERITY_COLOUR["Low"]

        # ----------------------------------------------------------------
        # Block Kit layout
        # ----------------------------------------------------------------
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🔍 Vulnerability Scan Complete — {target}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n`{target}`"},
                    {"type": "mrkdwn", "text": f"*Hostname:*\n`{hostname or 'N/A'}`"},
                    {"type": "mrkdwn", "text": f"*Scan time:*\n{result.get('scan_start', '')}"},
                    {"type": "mrkdwn", "text": f"*Total findings:*\n{total}"},
                ],
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"🔴 *Critical:* {critical}   "
                        f"🟠 *High:* {high}   "
                        f"🟡 *Medium:* {medium}   "
                        f"🟢 *Low:* {low}"
                    ),
                },
            },
        ]

        # Top 3 findings
        top_vulns = sorted(
            result.get("vulnerabilities", []),
            key=lambda v: v.get("cvss_score", 0),
            reverse=True,
        )[:3]

        if top_vulns:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*Top Findings:*"},
            })
            for v in top_vulns:
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"• `{v.get('script_id')}` on port `{v.get('port')}/{v.get('protocol')}`"
                            f" — *{v.get('severity')}* (CVSS {v.get('cvss_score')})"
                            + (f" `{v.get('cve')}`" if v.get("cve") else "")
                        ),
                    },
                })

        if report_url:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"📄 <{report_url}|View Full Report>",
                },
            })

        return {
            "attachments": [
                {
                    "color": colour,
                    "blocks": blocks,
                }
            ]
        }

    # ------------------------------------------------------------------
    # HTTP POST (stdlib only — no requests dependency needed here)
    # ------------------------------------------------------------------

    def _post(self, payload: dict) -> bool:
        data = json.dumps(payload).encode("utf-8")
        req  = request.Request(
            self.webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    logger.info("Slack notification sent successfully")
                    return True
                logger.error(f"Slack returned HTTP {resp.status}")
                return False
        except error.URLError as exc:
            logger.error(f"Failed to send Slack notification: {exc}")
            return False
