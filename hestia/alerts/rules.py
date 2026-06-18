"""
Alert rule engine for Hestia Shield.

Evaluates configurable rules against security events and determines
when to trigger notifications.
"""

import logging
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class AlertRule:
    """
    A single alert rule with a condition and severity.

    The condition receives stats context and returns True if the alert
    should fire.

    Usage:
        rule = AlertRule(
            name="high_block_rate",
            condition=lambda ctx: ctx.get("blocks_per_minute", 0) > 2,
            severity="critical",
            channels=["slack", "email"],
        )
    """

    def __init__(
        self,
        name: str,
        condition: Callable[[Dict[str, Any]], bool],
        severity: str = "high",
        channels: Optional[List[str]] = None,
        cooldown_seconds: int = 300,
        enabled: bool = True,
    ):
        self.name = name
        self.condition = condition
        self.severity = severity
        self.channels = channels or ["slack"]
        self.cooldown_seconds = cooldown_seconds
        self.enabled = enabled
        self._last_fired: float = 0.0

    def evaluate(self, context: Dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        if not self.condition(context):
            return False
        now = time.time()
        if now - self._last_fired < self.cooldown_seconds:
            return False
        self._last_fired = now
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "severity": self.severity,
            "channels": list(self.channels),
            "cooldown_seconds": self.cooldown_seconds,
            "enabled": self.enabled,
        }


class AlertRuleEngine:
    """
    Evaluates alert rules against security events and stats context.
    """

    def __init__(self):
        self._rules: Dict[str, AlertRule] = {}
        self._event_window: List[Dict] = []
        self._window_seconds = 300
        self._stats: Dict[str, Any] = {
            "total_evaluations": 0,
            "alerts_fired": 0,
            "rules_triggered": defaultdict(int),
        }

    def add_rule(self, rule: AlertRule) -> None:
        self._rules[rule.name] = rule

    def remove_rule(self, name: str) -> bool:
        if name in self._rules:
            del self._rules[name]
            return True
        return False

    def get_rule(self, name: str) -> Optional[AlertRule]:
        return self._rules.get(name)

    def list_rules(self) -> List[Dict]:
        return [r.to_dict() for r in self._rules.values()]

    def record_event(self, event: Dict) -> None:
        now = time.time()
        self._event_window.append({"time": now, **event})
        cutoff = now - self._window_seconds
        self._event_window = [e for e in self._event_window if e["time"] >= cutoff]

    def _build_context(self) -> Dict[str, Any]:
        now = time.time()
        cutoff = now - self._window_seconds
        recent = [e for e in self._event_window if e["time"] >= cutoff]

        total = len(recent)
        blocks = sum(1 for e in recent if e.get("decision") == "block")
        period_minutes = self._window_seconds / 60

        return {
            "total_events": total,
            "blocks": blocks,
            "blocks_per_minute": round(blocks / period_minutes, 2) if period_minutes else 0,
            "events_per_minute": round(total / period_minutes, 2) if period_minutes else 0,
            "window_seconds": self._window_seconds,
        }

    def evaluate(self, event: Optional[Dict] = None) -> List[Dict]:
        if event:
            self.record_event(event)

        context = self._build_context()
        fired: List[Dict] = []

        for rule in self._rules.values():
            self._stats["total_evaluations"] += 1
            if rule.evaluate(context):
                self._stats["alerts_fired"] += 1
                self._stats["rules_triggered"][rule.name] += 1
                fired.append({
                    "rule": rule.name,
                    "severity": rule.severity,
                    "channels": list(rule.channels),
                    "context": dict(context),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

        return fired

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_evaluations": self._stats["total_evaluations"],
            "alerts_fired": self._stats["alerts_fired"],
            "rules_triggered": dict(self._stats["rules_triggered"]),
            "active_rules": len(self._rules),
        }

    def reset_window(self) -> None:
        self._event_window.clear()
