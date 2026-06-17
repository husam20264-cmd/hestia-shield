"""
Background Worker for Hestia Shield v1.1.0

Processes tasks from Redis queues: webhook delivery, audit logging, event persistence.
"""

import os
import json
import asyncio
import logging
from typing import Dict, Optional
from datetime import datetime

from .queue import get_queue, Task, TaskHandler, Priority, QUEUE_CONFIG

logger = logging.getLogger(__name__)


class WebhookHandler(TaskHandler):
    """Delivers webhook events to subscribed URLs."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self._client = None

    async def _ensure_client(self):
        if not self._client:
            import httpx
            self._client = httpx.AsyncClient(timeout=self.timeout)

    async def handle(self, task: Task) -> bool:
        await self._ensure_client()
        payload = task.payload
        url = payload.get("url")
        event_data = payload.get("event_data", {})
        secret = payload.get("secret")

        if not url:
            logger.error("Webhook task missing URL")
            return False

        headers = {"Content-Type": "application/json"}
        body = json.dumps(event_data)

        if secret:
            import hashlib
            import hmac
            signature = hmac.new(
                secret.encode(), body.encode(), hashlib.sha256
            ).hexdigest()
            headers["X-Hestia-Signature"] = signature

        for attempt in range(3):
            try:
                response = await self._client.post(url, headers=headers, content=body)
                if response.status_code == 200:
                    logger.info(f"Webhook delivered to {url}")
                    return True
                logger.warning(
                    f"Webhook {url} returned {response.status_code} (attempt {attempt + 1})"
                )
            except Exception as e:
                logger.error(f"Webhook {url} failed: {e} (attempt {attempt + 1})")

            if attempt < 2:
                await asyncio.sleep(2 ** attempt)

        logger.error(f"Webhook {url} failed after 3 attempts")
        return False

    async def close(self):
        if self._client:
            await self._client.aclose()


class AuditLogHandler(TaskHandler):
    """Persists audit log entries to storage."""

    def __init__(self, storage):
        self.storage = storage

    async def handle(self, task: Task) -> bool:
        try:
            log_id = await self.storage.store_audit_log(task.payload)
            logger.debug(f"Audit log persisted: {log_id}")
            return True
        except Exception as e:
            logger.error(f"Audit log persistence failed: {e}")
            return False


class EventPersistHandler(TaskHandler):
    """Persists security events to storage."""

    def __init__(self, storage):
        self.storage = storage

    async def handle(self, task: Task) -> bool:
        try:
            event_id = await self.storage.store_event(task.payload)
            logger.debug(f"Event persisted: {event_id}")
            return True
        except Exception as e:
            logger.error(f"Event persistence failed: {e}")
            return False


class Worker:
    """
    Background worker that processes tasks from Redis queues.
    Runs in a separate process/thread and polls queues continuously.
    """

    def __init__(self, storage, redis_url: Optional[str] = None):
        self.storage = storage
        self._running = False
        self._queue = None
        self._handlers: Dict[str, TaskHandler] = {
            "webhook_delivery": WebhookHandler(),
            "audit_log": AuditLogHandler(storage),
            "event_persist": EventPersistHandler(storage),
        }

    async def start(self):
        self._queue = get_queue()
        for task_type, handler in self._handlers.items():
            self._queue.register_handler(task_type, handler)
        self._running = True
        logger.info("Worker started, polling queues...")

    async def stop(self):
        self._running = False
        for handler in self._handlers.values():
            if hasattr(handler, "close"):
                await handler.close()
        if self._queue and hasattr(self._queue, "close"):
            await self._queue.close()
        logger.info("Worker stopped")

    async def process_task(self, task: Task) -> bool:
        handler = self._handlers.get(task.task_type)
        if not handler:
            logger.warning(f"No handler for task_type={task.task_type}")
            return False

        try:
            success = await handler.handle(task)
            if success:
                logger.debug(f"Processed {task.task_type} task {task.id[:8]}")
            else:
                logger.warning(f"Failed {task.task_type} task {task.id[:8]}")
            return success
        except Exception as e:
            logger.error(f"Error processing {task.task_type} task: {e}")
            return False

    async def poll_once(self) -> int:
        """Poll all queues once, return number of tasks processed."""
        processed = 0

        for queue_name in ["webhooks", "events", "audit"]:
            queue_obj = self._queue
            if hasattr(queue_obj, "dequeue"):
                task = await queue_obj.dequeue(queue_name, timeout=1)
                if task:
                    success = await self.process_task(task)
                    if success:
                        processed += 1

        return processed

    async def poll_loop(self, interval: float = 0.1):
        """Continuous polling loop. Run in background task."""
        while self._running:
            try:
                await self.poll_once()
            except Exception as e:
                logger.error(f"Poll loop error: {e}")
            await asyncio.sleep(interval)

    def get_stats(self) -> Dict:
        queue_stats = self._queue.get_stats() if self._queue else {}
        return {
            "running": self._running,
            "handlers": list(self._handlers.keys()),
            "queue": queue_stats,
        }