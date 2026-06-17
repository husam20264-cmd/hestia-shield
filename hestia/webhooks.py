"""
Webhooks for Hestia Shield v1.1.0

Synchronous delivery via WebhookManager.
Async queue-based delivery via queue_webhook().
"""

import json
import logging
import hashlib
import hmac
from typing import Dict, List, Optional, Any
from datetime import datetime

import httpx

from .queue import get_queue, Task, Priority

logger = logging.getLogger(__name__)


class WebhookManager:
    """Synchronous webhook delivery client with retry logic."""

    def __init__(self, timeout: int = 10, max_retries: int = 3):
        self.timeout = timeout
        self.max_retries = max_retries
        self.client = httpx.AsyncClient(timeout=timeout)

    async def send_webhook(
        self,
        url: str,
        event_data: Dict,
        secret: Optional[str] = None
    ) -> bool:
        headers = {"Content-Type": "application/json"}
        body = json.dumps(event_data)

        if secret:
            signature = self._generate_signature(body, secret)
            headers["X-Hestia-Signature"] = signature

        for attempt in range(self.max_retries):
            try:
                response = await self.client.post(url, headers=headers, content=body)
                if response.status_code == 200:
                    logger.info(f"Webhook sent successfully to {url}")
                    return True
                logger.warning(
                    f"Webhook failed with status {response.status_code}: {response.text}"
                )
            except Exception as e:
                logger.error(f"Webhook attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries - 1:
                    continue

        logger.error(f"Webhook failed after {self.max_retries} attempts")
        return False

    def _generate_signature(self, payload: str, secret: str) -> str:
        return hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

    async def close(self):
        await self.client.aclose()


async def queue_webhook(
    tenant_id: str,
    url: str,
    event_data: Dict,
    secret: Optional[str] = None,
) -> bool:
    """Enqueue webhook delivery as a background task (high priority)."""
    from .queue import get_queue
    queue = get_queue()
    task = Task(
        task_type="webhook_delivery",
        payload={
            "tenant_id": tenant_id,
            "url": url,
            "event_data": event_data,
            "secret": secret,
        },
        priority=Priority.HIGH,
    )
    return await queue.enqueue(task)


async def queue_audit_log(
    tenant_id: str,
    audit_data: Dict,
) -> bool:
    """Enqueue audit log persistence as a background task (low priority)."""
    from .queue import get_queue
    queue = get_queue()
    task = Task(
        task_type="audit_log",
        payload={"tenant_id": tenant_id, **audit_data},
        priority=Priority.LOW,
    )
    return await queue.enqueue(task)


async def queue_event(
    tenant_id: str,
    event_data: Dict,
) -> bool:
    """Enqueue security event persistence as a background task (medium priority)."""
    from .queue import get_queue
    queue = get_queue()
    task = Task(
        task_type="event_persist",
        payload={"tenant_id": tenant_id, **event_data},
        priority=Priority.MEDIUM,
    )
    return await queue.enqueue(task)