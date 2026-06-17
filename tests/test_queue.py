"""
Tests for Task Queue (Redis / Null) v1.1.0
"""

import pytest
from hestia.queue import Task, TaskHandler, NullQueue, Priority


class TestTask:
    def test_task_creation(self):
        task = Task(task_type="webhook_delivery", payload={"url": "https://example.com"}, priority=Priority.HIGH)
        assert task.task_type == "webhook_delivery"
        assert task.payload["url"] == "https://example.com"
        assert task.priority == Priority.HIGH

    def test_task_round_trip(self):
        task = Task(task_type="audit_log", payload={"user_id": "usr_1"}, priority=Priority.LOW)
        data = task.to_dict()
        restored = Task.from_dict(data)
        assert restored.task_type == task.task_type
        assert restored.payload["user_id"] == "usr_1"
        assert restored.priority == task.priority
        assert restored.id == task.id


class FakeHandler(TaskHandler):
    def __init__(self):
        self.handled = []

    async def handle(self, task: Task) -> bool:
        self.handled.append(task)
        return True


class TestNullQueue:
    @pytest.mark.asyncio
    async def test_enqueue_processes_sync(self):
        queue = NullQueue()
        handler = FakeHandler()
        queue.register_handler("test_type", handler)

        task = Task(task_type="test_type", payload={"msg": "hello"})
        result = await queue.enqueue(task)

        assert result is True
        assert len(handler.handled) == 1
        assert handler.handled[0].payload["msg"] == "hello"

    @pytest.mark.asyncio
    async def test_enqueue_no_handler(self):
        queue = NullQueue()
        task = Task(task_type="unknown", payload={})
        result = await queue.enqueue(task)
        assert result is False

    @pytest.mark.asyncio
    async def test_enqueue_batch(self):
        queue = NullQueue()
        handler = FakeHandler()
        queue.register_handler("batch", handler)

        tasks = [Task(task_type="batch", payload={"i": i}) for i in range(5)]
        results = await queue.enqueue_batch(tasks)

        assert all(results)
        assert len(handler.handled) == 5

    def test_get_stats(self):
        queue = NullQueue()
        stats = queue.get_stats()
        assert stats["backend"] == "null"
        assert stats["enqueued"] >= 0


class TestWebhookQueue:
    @pytest.mark.asyncio
    async def test_queue_webhook_function(self):
        from hestia.webhooks import queue_webhook
        result = await queue_webhook("ten_1", "https://example.com/hook", {"event": "test"})
        assert result is not None

    @pytest.mark.asyncio
    async def test_queue_audit_log_function(self):
        from hestia.webhooks import queue_audit_log
        result = await queue_audit_log("ten_1", {"action": "test"})
        assert result is not None


class TestWorker:
    @pytest.mark.asyncio
    async def test_worker_processes_task(self):
        from hestia.worker import Worker
        from hestia.storage import Storage
        import tempfile
        from pathlib import Path

        temp_dir = tempfile.mkdtemp()
        storage = Storage(data_dir=Path(temp_dir), store_raw_inputs=False)
        await storage.initialize()

        worker = Worker(storage)
        await worker.start()

        task = Task(task_type="audit_log", payload={"tenant_id": "ten_1", "action": "test"})
        success = await worker.process_task(task)

        assert success is True

        logs = await storage.get_audit_logs("ten_1")
        assert len(logs) >= 1

        await worker.stop()
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_worker_stats(self):
        from hestia.worker import Worker
        from hestia.storage import Storage
        import tempfile
        from pathlib import Path

        temp_dir = tempfile.mkdtemp()
        storage = Storage(data_dir=Path(temp_dir), store_raw_inputs=False)
        await storage.initialize()

        worker = Worker(storage)
        await worker.start()

        stats = worker.get_stats()
        assert stats["running"] is True
        assert "audit_log" in stats["handlers"]

        await worker.stop()
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)