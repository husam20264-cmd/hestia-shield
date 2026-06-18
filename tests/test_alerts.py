"""
Tests for Hestia Shield — Alerting & Notifications
"""

import pytest
import time
import json
from unittest.mock import patch, MagicMock
from urllib.error import URLError

from hestia.alerts import (
    NotificationManager,
    AlertRule,
    AlertRuleEngine,
    SlackChannel,
    EmailChannel,
    PagerDutyChannel,
    WebhookChannel,
)


class TestAlertRule:
    """Tests for AlertRule."""

    def test_rule_evaluates_true(self):
        rule = AlertRule(
            name="test_rule",
            condition=lambda ctx: ctx.get("value", 0) > 5,
            severity="high",
        )
        assert rule.evaluate({"value": 10}) is True

    def test_rule_evaluates_false(self):
        rule = AlertRule(
            name="test_rule",
            condition=lambda ctx: ctx.get("value", 0) > 5,
        )
        assert rule.evaluate({"value": 3}) is False

    def test_rule_disabled(self):
        rule = AlertRule(
            name="test_rule",
            condition=lambda ctx: True,
            enabled=False,
        )
        assert rule.evaluate({}) is False

    def test_rule_cooldown(self):
        rule = AlertRule(
            name="test_rule",
            condition=lambda ctx: True,
            cooldown_seconds=3600,
        )
        assert rule.evaluate({}) is True
        assert rule.evaluate({}) is False  # within cooldown

    def test_rule_to_dict(self):
        rule = AlertRule(
            name="test_rule",
            condition=lambda ctx: True,
            severity="critical",
            channels=["slack", "pagerduty"],
        )
        d = rule.to_dict()
        assert d["name"] == "test_rule"
        assert d["severity"] == "critical"
        assert "slack" in d["channels"]


class TestAlertRuleEngine:
    """Tests for AlertRuleEngine."""

    def test_engine_empty(self):
        engine = AlertRuleEngine()
        fired = engine.evaluate({"decision": "block"})
        assert fired == []
        stats = engine.get_stats()
        assert stats["active_rules"] == 0

    def test_engine_with_rule(self):
        engine = AlertRuleEngine()
        engine.add_rule(AlertRule(
            name="high_blocks",
            condition=lambda ctx: ctx.get("blocks_per_minute", 0) > 1,
            severity="critical",
            cooldown_seconds=0,
        ))
        # Add events to trigger the rule (need > 1 block/min, window is 5 min)
        for _ in range(6):
            engine.record_event({"decision": "block"})
        fired = engine.evaluate()
        assert len(fired) >= 1
        assert fired[0]["rule"] == "high_blocks"
        assert fired[0]["severity"] == "critical"

    def test_engine_add_remove_rule(self):
        engine = AlertRuleEngine()
        rule = AlertRule("test", condition=lambda ctx: True)
        engine.add_rule(rule)
        assert len(engine.list_rules()) == 1
        engine.remove_rule("test")
        assert len(engine.list_rules()) == 0

    def test_engine_get_rule(self):
        engine = AlertRuleEngine()
        rule = AlertRule("test", condition=lambda ctx: True)
        engine.add_rule(rule)
        assert engine.get_rule("test") is rule
        assert engine.get_rule("nonexistent") is None

    def test_engine_reset_window(self):
        engine = AlertRuleEngine()
        engine.record_event({"decision": "block"})
        engine.reset_window()
        assert len(engine._event_window) == 0

    def test_engine_stats(self):
        engine = AlertRuleEngine()
        engine.add_rule(AlertRule(
            "test", condition=lambda ctx: True, cooldown_seconds=0,
        ))
        engine.evaluate({"decision": "block"})
        stats = engine.get_stats()
        assert stats["total_evaluations"] >= 1
        assert stats["alerts_fired"] >= 1

    def test_engine_list_rules(self):
        engine = AlertRuleEngine()
        engine.add_rule(AlertRule("a", condition=lambda ctx: True))
        engine.add_rule(AlertRule("b", condition=lambda ctx: False))
        rules = engine.list_rules()
        assert len(rules) == 2
        names = [r["name"] for r in rules]
        assert "a" in names
        assert "b" in names


class TestSlackChannel:
    """Tests for SlackChannel."""

    def test_slack_send_success(self):
        channel = SlackChannel(
            webhook_url="https://hooks.slack.com/test",
            min_severity="low",
        )
        with patch("hestia.alerts.channels.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MagicMock()
            result = channel.send({
                "rule": "test_alert",
                "severity": "high",
                "timestamp": "2025-01-01T00:00:00",
                "context": {"total_events": 10, "blocks": 5},
            })
            assert result is True

    def test_slack_send_skipped_low_severity(self):
        channel = SlackChannel(
            webhook_url="https://hooks.slack.com/test",
            min_severity="critical",
        )
        result = channel.send({
            "rule": "test",
            "severity": "low",
        })
        assert result is False

    def test_slack_send_failure(self):
        channel = SlackChannel(webhook_url="https://hooks.slack.com/test")
        with patch("hestia.alerts.channels.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = URLError("Connection failed")
            result = channel.send({
                "rule": "test",
                "severity": "high",
            })
            assert result is False


class TestEmailChannel:
    """Tests for EmailChannel."""

    def test_email_send_success(self):
        channel = EmailChannel(
            smtp_host="localhost",
            smtp_port=25,
            to_emails=["admin@example.com"],
            use_tls=False,
        )
        with patch("smtplib.SMTP") as mock_smtp:
            instance = MagicMock()
            mock_smtp.return_value.__enter__.return_value = instance
            result = channel.send({
                "rule": "test_alert",
                "severity": "critical",
                "timestamp": "2025-01-01T00:00:00",
                "context": {"total_events": 5, "blocks": 3},
            })
            assert result is True
            instance.sendmail.assert_called_once()

    def test_email_send_no_recipients(self):
        channel = EmailChannel(to_emails=[])
        result = channel.send({"rule": "test", "severity": "high"})
        assert result is False

    def test_email_send_low_severity_skipped(self):
        channel = EmailChannel(
            to_emails=["admin@example.com"],
            min_severity="critical",
        )
        result = channel.send({"rule": "test", "severity": "low"})
        assert result is False

    def test_email_with_auth(self):
        channel = EmailChannel(
            smtp_host="smtp.gmail.com",
            smtp_port=587,
            username="user@gmail.com",
            password="app_password",
            to_emails=["admin@example.com"],
        )
        with patch("smtplib.SMTP") as mock_smtp:
            instance = MagicMock()
            mock_smtp.return_value.__enter__.return_value = instance
            result = channel.send({
                "rule": "test",
                "severity": "critical",
            })
            assert result is True
            instance.starttls.assert_called_once()
            instance.login.assert_called_once_with("user@gmail.com", "app_password")


class TestPagerDutyChannel:
    """Tests for PagerDutyChannel."""

    def test_pagerduty_send_success(self):
        channel = PagerDutyChannel(routing_key="test_key")
        with patch("hestia.alerts.channels.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MagicMock()
            result = channel.send({
                "rule": "critical_block",
                "severity": "critical",
                "context": {"blocks": 10},
            })
            assert result is True

    def test_pagerduty_skipped_low_severity(self):
        channel = PagerDutyChannel(routing_key="test_key")
        result = channel.send({"rule": "test", "severity": "low"})
        assert result is False

    def test_pagerduty_send_failure(self):
        channel = PagerDutyChannel(routing_key="test_key")
        with patch("hestia.alerts.channels.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = URLError("API down")
            result = channel.send({
                "rule": "test",
                "severity": "critical",
            })
            assert result is False


class TestWebhookChannel:
    """Tests for WebhookChannel."""

    def test_webhook_send_success(self):
        channel = WebhookChannel(
            url="https://example.com/webhook",
            headers={"X-API-Key": "secret"},
        )
        with patch("hestia.alerts.channels.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MagicMock()
            result = channel.send({
                "rule": "test",
                "severity": "high",
            })
            assert result is True

    def test_webhook_send_failure(self):
        channel = WebhookChannel(url="https://example.com/webhook")
        with patch("hestia.alerts.channels.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = URLError("timeout")
            result = channel.send({
                "rule": "test",
                "severity": "high",
            })
            assert result is False


class TestNotificationManager:
    """Tests for NotificationManager."""

    def test_manager_add_remove_channel(self):
        manager = NotificationManager()
        channel = SlackChannel(webhook_url="https://hooks.slack.com/test")
        manager.add_channel(channel)
        assert len(manager.list_channels()) == 1
        manager.remove_channel("slack")
        assert len(manager.list_channels()) == 0

    def test_manager_get_channel(self):
        manager = NotificationManager()
        channel = SlackChannel(webhook_url="https://hooks.slack.com/test")
        manager.add_channel(channel)
        assert manager.get_channel("slack") is channel
        assert manager.get_channel("nonexistent") is None

    def test_manager_process_event_dispatches(self):
        manager = NotificationManager()
        manager.add_channel(SlackChannel(
            webhook_url="https://hooks.slack.com/test",
            min_severity="low",
        ))
        manager.add_rule(AlertRule(
            name="high_blocks",
            condition=lambda ctx: True,
            severity="high",
            channels=["slack"],
            cooldown_seconds=0,
        ))

        with patch("hestia.alerts.channels.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MagicMock()
            result = manager.process_event({"decision": "block"})
            assert len(result) >= 1
            assert result[0]["dispatched"].get("slack") is True

    def test_manager_dispatch_to_missing_channel(self):
        manager = NotificationManager()
        manager.add_rule(AlertRule(
            name="test",
            condition=lambda ctx: True,
            channels=["slack"],  # no slack channel added
            cooldown_seconds=0,
        ))
        result = manager.process_event({"decision": "block"})
        if result:
            assert result[0]["dispatched"].get("slack") is False

    def test_manager_get_stats(self):
        manager = NotificationManager()
        stats = manager.get_stats()
        assert "channels" in stats
        assert "rules" in stats
        assert "engine" in stats
        assert "total_dispatched" in stats

    def test_manager_get_dispatch_log(self):
        manager = NotificationManager()
        log = manager.get_dispatch_log()
        assert isinstance(log, list)
