"""
Notification channels for Hestia Shield alerts.

Supports Slack, Email, PagerDuty, and generic webhook channels.
"""

import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger(__name__)


class NotificationChannel(ABC):
    """Base class for notification channels."""

    def __init__(self, name: str, min_severity: str = "low"):
        self.name = name
        self._severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        self._min_level = self._severity_order.get(min_severity, 4)

    def should_send(self, severity: str) -> bool:
        return self._severity_order.get(severity, 4) <= self._min_level

    @abstractmethod
    def send(self, alert: Dict[str, Any]) -> bool:
        ...


class SlackChannel(NotificationChannel):
    """
    Send alerts to a Slack channel via Incoming Webhook.

    Usage:
        channel = SlackChannel(
            webhook_url="https://hooks.slack.com/services/xxx",
            min_severity="high",
        )
    """

    def __init__(
        self,
        webhook_url: str,
        name: str = "slack",
        min_severity: str = "low",
    ):
        super().__init__(name, min_severity)
        self.webhook_url = webhook_url

    def send(self, alert: Dict) -> bool:
        if not self.should_send(alert.get("severity", "info")):
            return False

        severity = alert.get("severity", "info").upper()
        emoji = {
            "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
            "LOW": "🟢", "INFO": "🔵",
        }.get(severity, "🔵")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Hestia Shield Alert: {alert.get('rule', 'Unknown')}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:* {severity}"},
                    {"type": "mrkdwn", "text": f"*Time:* {alert.get('timestamp', 'N/A')}"},
                ],
            },
        ]

        context = alert.get("context", {})
        if context:
            fields = [
                {"type": "mrkdwn", "text": f"*Events:* {context.get('total_events', 0)}"},
                {"type": "mrkdwn", "text": f"*Blocks:* {context.get('blocks', 0)}"},
            ]
            blocks.append({"type": "section", "fields": fields})

        payload = json.dumps({"blocks": blocks}).encode()
        req = Request(
            self.webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )

        try:
            urlopen(req, timeout=10)
            logger.info("Slack alert sent: %s", alert.get("rule"))
            return True
        except URLError as e:
            logger.error("Slack notification failed: %s", e)
            return False


class EmailChannel(NotificationChannel):
    """
    Send alerts via SMTP email.

    Usage:
        channel = EmailChannel(
            smtp_host="smtp.gmail.com",
            smtp_port=587,
            username="user@gmail.com",
            password="app_password",
            from_addr="hestia@example.com",
            to_emails=["admin@example.com"],
        )
    """

    def __init__(
        self,
        smtp_host: str = "localhost",
        smtp_port: int = 25,
        username: Optional[str] = None,
        password: Optional[str] = None,
        from_addr: str = "hestia-shield@localhost",
        to_emails: Optional[List[str]] = None,
        use_tls: bool = True,
        name: str = "email",
        min_severity: str = "medium",
    ):
        super().__init__(name, min_severity)
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.to_emails = to_emails or []
        self.use_tls = use_tls

    def send(self, alert: Dict) -> bool:
        if not self.should_send(alert.get("severity", "info")):
            return False
        if not self.to_emails:
            logger.warning("EmailChannel: no recipients configured")
            return False

        try:
            import smtplib
            from email.mime.text import MIMEText

            severity = alert.get("severity", "info").upper()
            rule = alert.get("rule", "Unknown")
            timestamp = alert.get("timestamp", "N/A")
            context = alert.get("context", {})

            body = f"""
Hestia Shield Alert
====================
Rule: {rule}
Severity: {severity}
Time: {timestamp}

Context:
  Total Events: {context.get('total_events', 0)}
  Blocks: {context.get('blocks', 0)}
  Blocks/min: {context.get('blocks_per_minute', 0)}
  Events/min: {context.get('events_per_minute', 0)}
"""

            msg = MIMEText(body.strip())
            msg["Subject"] = f"[Hestia Shield] {severity}: {rule}"
            msg["From"] = self.from_addr
            msg["To"] = ", ".join(self.to_emails)

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.sendmail(self.from_addr, self.to_emails, msg.as_string())

            logger.info("Email alert sent: %s", rule)
            return True

        except Exception as e:
            logger.error("Email notification failed: %s", e)
            return False


class PagerDutyChannel(NotificationChannel):
    """
    Send critical alerts to PagerDuty via Events API v2.

    Usage:
        channel = PagerDutyChannel(
            routing_key="your_pagerduty_routing_key",
            min_severity="critical",
        )
    """

    def __init__(
        self,
        routing_key: str,
        name: str = "pagerduty",
        min_severity: str = "critical",
    ):
        super().__init__(name, min_severity)
        self.routing_key = routing_key
        self.api_url = "https://events.pagerduty.com/v2/enqueue"

    def send(self, alert: Dict) -> bool:
        if not self.should_send(alert.get("severity", "info")):
            return False

        severity_map = {
            "critical": "critical", "high": "error",
            "medium": "warning", "low": "info", "info": "info",
        }
        pd_severity = severity_map.get(alert.get("severity", "info"), "info")

        payload = json.dumps({
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"Hestia Shield: {alert.get('rule', 'Alert')}",
                "severity": pd_severity,
                "source": "hestia-shield",
                "custom_details": alert.get("context", {}),
            },
        }).encode()

        req = Request(
            self.api_url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )

        try:
            urlopen(req, timeout=10)
            logger.info("PagerDuty alert sent: %s", alert.get("rule"))
            return True
        except URLError as e:
            logger.error("PagerDuty notification failed: %s", e)
            return False


class WebhookChannel(NotificationChannel):
    """
    Send alerts to any HTTP endpoint.

    Usage:
        channel = WebhookChannel(
            url="https://example.com/webhook",
            headers={"X-API-Key": "secret"},
        )
    """

    def __init__(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        name: str = "webhook",
        min_severity: str = "low",
    ):
        super().__init__(name, min_severity)
        self.url = url
        self.headers = headers or {}

    def send(self, alert: Dict) -> bool:
        if not self.should_send(alert.get("severity", "info")):
            return False

        payload = json.dumps(alert).encode()
        headers = {**self.headers, "Content-Type": "application/json"}
        req = Request(self.url, data=payload, headers=headers)

        try:
            urlopen(req, timeout=10)
            logger.info("Webhook alert sent to %s", self.url)
            return True
        except URLError as e:
            logger.error("Webhook notification failed: %s", e)
            return False
