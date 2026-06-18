"""
Notification manager for Hestia Shield alerts.

Orchestrates alert rules and notification channels.
Processes security events and routes alerts to configured channels.
"""

import logging
from typing import Any, Dict, List, Optional

from .rules import AlertRule, AlertRuleEngine
from .channels import (
    NotificationChannel,
    SlackChannel,
    EmailChannel,
    PagerDutyChannel,
    WebhookChannel,
)

logger = logging.getLogger(__name__)


class NotificationManager:
    """
    Central manager for alert rules and notification channels.

    Usage:
        manager = NotificationManager()
        manager.add_channel(SlackChannel(webhook_url="..."))
        manager.add_rule(AlertRule(name="high_blocks", condition=lambda ctx: ...))
        manager.process_event({"decision": "block", ...})
    """

    def __init__(self):
        self._engine = AlertRuleEngine()
        self._channels: Dict[str, NotificationChannel] = {}
        self._dispatch_log: List[Dict] = []

    def add_channel(self, channel: NotificationChannel) -> None:
        self._channels[channel.name] = channel

    def remove_channel(self, name: str) -> bool:
        if name in self._channels:
            del self._channels[name]
            return True
        return False

    def get_channel(self, name: str) -> Optional[NotificationChannel]:
        return self._channels.get(name)

    def list_channels(self) -> List[Dict]:
        return [
            {"name": ch.name, "type": ch.__class__.__name__}
            for ch in self._channels.values()
        ]

    def add_rule(self, rule: AlertRule) -> None:
        self._engine.add_rule(rule)

    def remove_rule(self, name: str) -> bool:
        return self._engine.remove_rule(name)

    def list_rules(self) -> List[Dict]:
        return self._engine.list_rules()

    def process_event(self, event: Dict) -> List[Dict]:
        """
        Process a security event: evaluate rules and dispatch alerts.

        Returns list of dispatched alerts.
        """
        fired = self._engine.evaluate(event)
        dispatched = []

        for alert in fired:
            result = self._dispatch(alert)
            dispatched.append({**alert, "dispatched": result})

        return dispatched

    def _dispatch(self, alert: Dict) -> Dict[str, bool]:
        results = {}
        for channel_name in alert.get("channels", ["slack"]):
            channel = self._channels.get(channel_name)
            if channel:
                success = channel.send(alert)
                results[channel_name] = success
                self._dispatch_log.append({
                    "alert": alert["rule"],
                    "channel": channel_name,
                    "success": success,
                    "timestamp": alert.get("timestamp", ""),
                })
            else:
                logger.warning("Channel '%s' not configured", channel_name)
                results[channel_name] = False

        return results

    def get_stats(self) -> Dict[str, Any]:
        return {
            "channels": len(self._channels),
            "rules": len(self._engine._rules),
            "engine": self._engine.get_stats(),
            "total_dispatched": len(self._dispatch_log),
        }

    def get_dispatch_log(self, limit: int = 50) -> List[Dict]:
        return self._dispatch_log[-limit:]
