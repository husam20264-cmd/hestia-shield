"""
Redis Task Queue for Hestia Shield v1.1.0

Provides async task queues with priority levels and Redis/NULL backends.
Queues: webhooks (high), events (medium), audit (low).
"""

import os
import json
import uuid
import logging
from abc import ABC, abstractmethod
from enum import IntEnum
from typing import Callable, Dict, List, Optional, Any
from datetime import datetime

from .telemetry import get_meter

logger = logging.getLogger(__name__)
_queue_meter = get_meter("hestia.queue")
_queue_depth = _queue_meter.create_histogram("queue.depth")
_queue_enqueued = _queue_meter.create_counter("queue.enqueued")
_queue_processed = _queue_meter.create_counter("queue.processed")
_queue_failed = _queue_meter.create_counter("queue.failed")

logger = logging.getLogger(__name__)


class Priority(IntEnum):
    HIGH = 10
    MEDIUM = 5
    LOW = 1


QUEUE_CONFIG = {
    "webhooks": {"redis_key": "hestia:queue:webhooks", "priority": Priority.HIGH},
    "events": {"redis_key": "hestia:queue:events", "priority": Priority.MEDIUM},
    "audit": {"redis_key": "hestia:queue:audit", "priority": Priority.LOW},
}


class Task:
    def __init__(
        self,
        task_type: str,
        payload: Dict,
        priority: Priority = Priority.MEDIUM,
        task_id: Optional[str] = None,
    ):
        self.id = task_id or str(uuid.uuid4())
        self.task_type = task_type
        self.payload = payload
        self.priority = priority
        self.created_at = datetime.now().isoformat()
        self.retries = 0
        self.max_retries = 3

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "task_type": self.task_type,
            "payload": self.payload,
            "priority": self.priority.value,
            "created_at": self.created_at,
            "retries": self.retries,
            "max_retries": self.max_retries,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "Task":
        task = cls(
            task_type=data["task_type"],
            payload=data["payload"],
            priority=Priority(data.get("priority", 5)),
            task_id=data.get("id"),
        )
        task.created_at = data.get("created_at", task.created_at)
        task.retries = data.get("retries", 0)
        task.max_retries = data.get("max_retries", 3)
        return task


class TaskHandler(ABC):
    @abstractmethod
    async def handle(self, task: Task) -> bool:
        ...


class NullQueue:
    """Fallback queue: processes tasks synchronously when Redis is unavailable."""

    def __init__(self):
        self.handlers: Dict[str, TaskHandler] = {}
        self._stats = {"enqueued": 0, "processed": 0, "failed": 0}

    def register_handler(self, task_type: str, handler: TaskHandler):
        self.handlers[task_type] = handler

    async def enqueue(self, task: Task) -> bool:
        self._stats["enqueued"] += 1
        _queue_enqueued.add(1, {"task_type": task.task_type, "backend": "null"})
        handler = self.handlers.get(task.task_type)
        if handler:
            try:
                success = await handler.handle(task)
                if success:
                    self._stats["processed"] += 1
                    _queue_processed.add(1, {"task_type": task.task_type, "backend": "null"})
                else:
                    self._stats["failed"] += 1
                    _queue_failed.add(1, {"task_type": task.task_type, "backend": "null"})
                return success
            except Exception as e:
                logger.error(f"NullQueue handler failed for {task.task_type}: {e}")
                self._stats["failed"] += 1
                _queue_failed.add(1, {"task_type": task.task_type, "backend": "null"})
                return False
        logger.warning(f"No handler registered for task_type={task.task_type}")
        return False

    async def enqueue_batch(self, tasks: List[Task]) -> List[bool]:
        return [await self.enqueue(t) for t in tasks]

    def get_stats(self) -> Dict:
        return {**self._stats, "backend": "null"}

    async def close(self):
        pass


class RedisQueue:
    """Redis-backed task queue with priority support."""

    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self.handlers: Dict[str, TaskHandler] = {}
        self._redis = None
        self._initialized = False
        self._stats = {"enqueued": 0, "processed": 0, "failed": 0}

    def register_handler(self, task_type: str, handler: TaskHandler):
        self.handlers[task_type] = handler

    async def _ensure_redis(self):
        if not self._initialized:
            try:
                import redis.asyncio as redis
                self._redis = redis.from_url(
                    self.redis_url,
                    max_connections=20,
                    decode_responses=True
                )
                await self._redis.ping()
                self._initialized = True
                logger.info(f"Connected to Redis queue at {self.redis_url}")
            except Exception as e:
                logger.warning(f"Redis queue connection failed: {e}, falling back to NullQueue")
                self._initialized = False
                self._redis = None

    async def enqueue(self, task: Task) -> bool:
        await self._ensure_redis()
        if not self._redis:
            return await NullQueue().enqueue(task)

        try:
            config = next(
                (c for c in QUEUE_CONFIG.values() if c["priority"] == task.priority),
                QUEUE_CONFIG["events"]
            )
            key = QUEUE_CONFIG.get(task.task_type, {}).get("redis_key", "hestia:queue:default")
            score = task.priority.value
            await self._redis.zadd(key, {json.dumps(task.to_dict()): score})
            self._stats["enqueued"] += 1
            _queue_enqueued.add(1, {"task_type": task.task_type, "backend": "redis"})
            return True
        except Exception as e:
            logger.error(f"Redis enqueue failed: {e}")
            _queue_failed.add(1, {"task_type": task.task_type, "backend": "redis"})
            return False

    async def enqueue_batch(self, tasks: List[Task]) -> List[bool]:
        return [await self.enqueue(t) for t in tasks]

    async def dequeue(self, queue_name: str, timeout: int = 5) -> Optional[Task]:
        await self._ensure_redis()
        if not self._redis:
            return None

        try:
            key = f"hestia:queue:{queue_name}"
            result = await self._redis.bzpopmin(key, timeout=timeout)
            if result:
                _, data_json, _ = result
                data = json.loads(data_json)
                task = Task.from_dict(data)
                _queue_processed.add(1, {"task_type": task.task_type, "backend": "redis"})
                depth = await self._redis.zcard(key)
                _queue_depth.record(depth, {"queue": queue_name})
                return task
        except Exception as e:
            logger.error(f"Redis dequeue failed: {e}")

    async def dequeue_all(self, queue_name: str) -> List[Task]:
        await self._ensure_redis()
        if not self._redis:
            return []

        try:
            key = f"hestia:queue:{queue_name}"
            results = await self._redis.zpopmin(key, count=100)
            tasks = []
            for data_json, _ in results:
                data = json.loads(data_json)
                tasks.append(Task.from_dict(data))
            return tasks
        except Exception as e:
            logger.error(f"Redis dequeue all failed: {e}")
            return []

    async def queue_size(self, queue_name: str) -> int:
        await self._ensure_redis()
        if not self._redis:
            return 0
        try:
            return await self._redis.zcard(f"hestia:queue:{queue_name}")
        except:
            return 0

    def get_stats(self) -> Dict:
        return {**self._stats, "backend": "redis" if self._initialized else "null"}

    async def close(self):
        if self._redis:
            await self._redis.close()


_queue_instance = None


def get_queue() -> NullQueue:
    global _queue_instance
    if _queue_instance is not None:
        return _queue_instance

    redis_url = os.getenv("HESTIA_REDIS_URL", "")
    if redis_url:
        _queue_instance = RedisQueue(redis_url)
    else:
        _queue_instance = NullQueue()
    return _queue_instance


def configure_queue(storage=None) -> NullQueue:
    """
    Create and configure a queue with default handlers pre-registered.
    This ensures NullQueue processes tasks inline without needing a Worker.
    Call once at application startup.
    """
    from .worker import WebhookHandler, AuditLogHandler, EventPersistHandler

    queue = get_queue()

    webhook_handler = WebhookHandler()
    audit_handler = AuditLogHandler(storage) if storage else None
    event_handler = EventPersistHandler(storage) if storage else None

    queue.register_handler("webhook_delivery", webhook_handler)
    if audit_handler:
        queue.register_handler("audit_log", audit_handler)
    if event_handler:
        queue.register_handler("event_persist", event_handler)

    return queue