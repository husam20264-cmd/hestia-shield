"""
Webhooks tests for Hestia Shield v1.0.0
"""

import pytest


class TestWebhooks:
    def test_webhook_manager(self):
        from hestia.webhooks import WebhookManager

        manager = WebhookManager(timeout=5, max_retries=2)
        assert manager.timeout == 5
        assert manager.max_retries == 2

    def test_webhook_signature(self):
        from hestia.webhooks import WebhookManager

        manager = WebhookManager()
        signature = manager._generate_signature("test", "secret")
        assert len(signature) == 64