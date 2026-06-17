"""
SQLite Storage Engine for Hestia Shield v1.1.0

Implements StorageBackend using JSON file-based storage with thread-safe operations.
Suitable for development and single-node deployments.
"""

import json
import uuid
import secrets
import logging
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

from .storage_base import StorageBackend

logger = logging.getLogger(__name__)


class ThreadSafeFile:
    """Thread-safe file operations with per-file locking."""

    def __init__(self, path: Path, default: str = "[]"):
        self.path = path
        self.default = default
        self._lock = threading.RLock()

    def read_text(self) -> str:
        with self._lock:
            if not self.path.exists() or self.path.stat().st_size == 0:
                return self.default
            return self.path.read_text()

    def write_text(self, data: str):
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(data)

    def read_json(self):
        return json.loads(self.read_text())

    def write_json(self, data):
        self.write_text(json.dumps(data, indent=2))


class Storage(StorageBackend):
    def __init__(self, data_dir: Optional[str] = None, store_raw_inputs: bool = False):
        self.data_dir = Path(data_dir) if data_dir else Path("./data")
        self.store_raw_inputs = store_raw_inputs
        self._initialized = False

        self._tenants = ThreadSafeFile(self.data_dir / "tenants.json", "[]")
        self._api_keys = ThreadSafeFile(self.data_dir / "api_keys.json", "[]")
        self._webhooks = ThreadSafeFile(self.data_dir / "webhooks.json", "[]")
        self._events = ThreadSafeFile(self.data_dir / "events.json", "[]")
        self._audit = ThreadSafeFile(self.data_dir / "audit.json", "[]")
        self._alerts = ThreadSafeFile(self.data_dir / "alerts.json", "[]")
        self._agents = ThreadSafeFile(self.data_dir / "agents.json", "[]")
        self._stats = ThreadSafeFile(self.data_dir / "stats.json", "[]")

    async def initialize(self) -> None:
        if self._initialized:
            return
        for f in [self._tenants, self._api_keys, self._webhooks,
                  self._events, self._audit, self._alerts,
                  self._agents, self._stats]:
            f.write_text(f.default)
        self._initialized = True
        logger.info(f"SQLite storage initialized at {self.data_dir}")

    async def close(self) -> None:
        self._initialized = False

    async def create_tenant(self, tenant_id: str, name: str, config: Optional[Dict] = None) -> Dict:
        tenants = self._tenants.read_json()
        if any(t["tenant_id"] == tenant_id for t in tenants):
            raise ValueError(f"Tenant {tenant_id} already exists")
        tenant = {
            "tenant_id": tenant_id,
            "name": name,
            "config": config or {},
            "created_at": datetime.now().isoformat(),
            "status": "active"
        }
        tenants.append(tenant)
        self._tenants.write_json(tenants)
        return tenant

    async def get_tenant(self, tenant_id: str) -> Optional[Dict]:
        tenants = self._tenants.read_json()
        for t in tenants:
            if t["tenant_id"] == tenant_id:
                return t
        return None

    async def list_tenants(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        tenants = self._tenants.read_json()
        return tenants[offset:offset + limit]

    async def create_api_key(self, tenant_id: str, role: str = "admin") -> Dict:
        import hashlib
        api_keys = self._api_keys.read_json()
        key_id = f"hst_{uuid.uuid4().hex[:8]}"
        secret = secrets.token_urlsafe(32)
        full_key = f"{key_id}_{secret}"
        key_hash = hashlib.sha256(full_key.encode()).hexdigest()
        api_key = {
            "key_id": key_id,
            "key_hash": key_hash,
            "tenant_id": tenant_id,
            "role": role,
            "created_at": datetime.now().isoformat(),
            "last_used": None,
            "is_active": True
        }
        api_keys.append(api_key)
        self._api_keys.write_json(api_keys)
        return {"key": full_key, "key_id": key_id, "tenant_id": tenant_id, "role": role}

    async def validate_api_key(self, api_key: str) -> Optional[Dict]:
        import hashlib
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        api_keys = self._api_keys.read_json()
        for key_data in api_keys:
            if key_data.get("key_hash") == key_hash and key_data.get("is_active", True):
                key_data["last_used"] = datetime.now().isoformat()
                self._api_keys.write_json(api_keys)
                return key_data
        return None

    async def revoke_api_key(self, api_key: str) -> bool:
        import hashlib
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        api_keys = self._api_keys.read_json()
        for key_data in api_keys:
            if key_data.get("key_hash") == key_hash:
                key_data["is_active"] = False
                self._api_keys.write_json(api_keys)
                return True
        return False

    async def store_event(self, event_data: Dict) -> str:
        events = self._events.read_json()
        event_id = event_data.get("id", str(uuid.uuid4()))
        entry = {
            "id": event_id,
            "data": event_data,
            "timestamp": datetime.now().isoformat()
        }
        events.append(entry)
        if len(events) > 20000:
            events = events[-10000:]
        self._events.write_json(events)
        return event_id

    async def get_events(self, tenant_id: Optional[str] = None, event_type: Optional[str] = None,
                         limit: int = 100, offset: int = 0) -> List[Dict]:
        events = self._events.read_json()
        filtered = []
        for e in events:
            data = e.get("data", {})
            if tenant_id and data.get("tenant_id") != tenant_id:
                continue
            if event_type and data.get("event_type") != event_type:
                continue
            filtered.append(e)
        return filtered[offset:offset + limit]

    async def count_events(self, tenant_id: str, hours: int = 24) -> int:
        from datetime import timedelta
        cutoff = datetime.now() - timedelta(hours=hours)
        events = self._events.read_json()
        count = 0
        for e in events:
            data = e.get("data", {})
            if data.get("tenant_id") != tenant_id:
                continue
            ts = e.get("timestamp", "")
            try:
                if datetime.fromisoformat(ts) >= cutoff:
                    count += 1
            except ValueError:
                count += 1
        return count

    async def store_audit_log(self, audit_data: Dict) -> str:
        logs = self._audit.read_json()
        log_id = str(uuid.uuid4())
        log_entry = {"id": log_id, **audit_data, "timestamp": datetime.now().isoformat()}
        logs.append(log_entry)
        if len(logs) > 20000:
            logs = logs[-10000:]
        self._audit.write_json(logs)
        return log_id

    async def get_audit_logs(self, tenant_id: str, user_id: Optional[str] = None,
                             limit: int = 100) -> List[Dict]:
        logs = self._audit.read_json()
        filtered = []
        for log in logs:
            if log.get("tenant_id") != tenant_id:
                continue
            if user_id and log.get("user_id") != user_id:
                continue
            filtered.append(log)
        return filtered[-limit:]

    async def create_webhook(self, tenant_id: str, url: str, events: List[str],
                             secret: Optional[str] = None) -> Dict:
        webhooks = self._webhooks.read_json()
        webhook_id = f"wh_{uuid.uuid4().hex[:8]}"
        webhook = {
            "id": webhook_id,
            "tenant_id": tenant_id,
            "url": url,
            "events": events,
            "secret": secret,
            "is_active": True,
            "created_at": datetime.now().isoformat(),
            "last_triggered_at": None,
            "failure_count": 0
        }
        webhooks.append(webhook)
        self._webhooks.write_json(webhooks)
        return webhook

    async def get_webhooks_for_tenant(self, tenant_id: str) -> List[Dict]:
        webhooks = self._webhooks.read_json()
        return [
            w for w in webhooks
            if w["tenant_id"] == tenant_id and w.get("is_active", True)
        ]

    async def update_webhook(self, webhook_id: str, updates: Dict) -> bool:
        webhooks = self._webhooks.read_json()
        for w in webhooks:
            if w["id"] == webhook_id:
                w.update(updates)
                w["updated_at"] = datetime.now().isoformat()
                self._webhooks.write_json(webhooks)
                return True
        return False

    async def delete_webhook(self, webhook_id: str) -> bool:
        webhooks = self._webhooks.read_json()
        new_webhooks = [w for w in webhooks if w["id"] != webhook_id]
        if len(new_webhooks) == len(webhooks):
            return False
        self._webhooks.write_json(new_webhooks)
        return True

    async def create_agent_profile(self, agent_data: Dict) -> Dict:
        agents = self._agents.read_json()
        profile = {**agent_data, "created_at": datetime.now().isoformat()}
        agents.append(profile)
        self._agents.write_json(agents)
        return profile

    async def get_agent_profile(self, agent_id: str) -> Optional[Dict]:
        agents = self._agents.read_json()
        for a in agents:
            if a.get("agent_id") == agent_id:
                return a
        return None

    async def update_agent_profile(self, agent_id: str, updates: Dict) -> bool:
        agents = self._agents.read_json()
        for a in agents:
            if a.get("agent_id") == agent_id:
                a.update(updates)
                a["updated_at"] = datetime.now().isoformat()
                self._agents.write_json(agents)
                return True
        return False

    async def create_alert(self, alert_data: Dict) -> str:
        alerts = self._alerts.read_json()
        alert_id = str(uuid.uuid4())
        alert = {"id": alert_id, **alert_data, "created_at": datetime.now().isoformat(), "status": "open"}
        alerts.append(alert)
        self._alerts.write_json(alerts)
        return alert_id

    async def get_alerts(self, tenant_id: str, status: Optional[str] = None,
                         limit: int = 100) -> List[Dict]:
        alerts = self._alerts.read_json()
        filtered = []
        for a in alerts:
            if a.get("tenant_id") != tenant_id:
                continue
            if status and a.get("status") != status:
                continue
            filtered.append(a)
        return filtered[-limit:]

    async def update_alert(self, alert_id: str, updates: Dict) -> bool:
        alerts = self._alerts.read_json()
        for a in alerts:
            if a["id"] == alert_id:
                a.update(updates)
                a["updated_at"] = datetime.now().isoformat()
                self._alerts.write_json(alerts)
                return True
        return False

    async def get_daily_stats(self, tenant_id: str, date: datetime) -> Dict:
        stats = self._stats.read_json()
        date_str = date.strftime("%Y-%m-%d")
        for s in stats:
            if s.get("tenant_id") == tenant_id and s.get("date") == date_str:
                return s
        return {"tenant_id": tenant_id, "date": date_str, "events": 0, "blocked": 0}

    async def update_daily_stats(self, tenant_id: str, date: datetime, new_stats: Dict) -> None:
        stats = self._stats.read_json()
        date_str = date.strftime("%Y-%m-%d")
        for s in stats:
            if s.get("tenant_id") == tenant_id and s.get("date") == date_str:
                s.update(new_stats)
                self._stats.write_json(stats)
                return
        stats.append({"tenant_id": tenant_id, "date": date_str, **new_stats})
        self._stats.write_json(stats)

    async def health_check(self) -> Dict:
        return {
            "backend": "sqlite",
            "status": "healthy",
            "data_dir": str(self.data_dir)
        }