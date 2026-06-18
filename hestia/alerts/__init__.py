"""
Hestia Shield — Alerting & Notifications

Provides alert rules, notification channels, and a notification manager
for routing security alerts to Slack, Email, PagerDuty, and webhooks.

Usage:
    from hestia.alerts import NotificationManager, AlertRule, SlackChannel

    manager = NotificationManager()
    manager.add_channel(SlackChannel(webhook_url="https://hooks.slack.com/..."))
    manager.add_rule(AlertRule(
        name="high_block_rate",
        condition=lambda ctx: ctx.get("blocks_per_minute", 0) > 2,
        severity="critical",
    ))
    manager.process_event({"decision": "block"})
"""

from .manager import NotificationManager
from .rules import AlertRule, AlertRuleEngine
from .channels import (
    SlackChannel,
    EmailChannel,
    PagerDutyChannel,
    WebhookChannel,
)

__all__ = [
    "NotificationManager",
    "AlertRule",
    "AlertRuleEngine",
    "SlackChannel",
    "EmailChannel",
    "PagerDutyChannel",
    "WebhookChannel",
]
