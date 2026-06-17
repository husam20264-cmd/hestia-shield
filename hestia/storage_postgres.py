"""
PostgreSQL Storage Engine for Hestia Shield v1.1.0

Production-grade storage backend using SQLAlchemy async + asyncpg.
"""

import os
import uuid
import secrets
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import text, MetaData, Table, Column, String, Integer, Float, Boolean, DateTime, Text, JSON

from .storage_base import StorageBackend

logger = logging.getLogger(__name__)

metadata = MetaData()

tenants_table = Table(
    "tenants", metadata,
    Column("tenant_id", String(64), primary_key=True),
    Column("name", String(256), nullable=False),
    Column("config", JSON),
    Column("status", String(32), default="active"),
    Column("created_at", DateTime, default=datetime.now),
)

api_keys_table = Table(
    "api_keys", metadata,
    Column("key_hash", String(256), primary_key=True),
    Column("key_id", String(64), nullable=False),
    Column("tenant_id", String(64), nullable=False),
    Column("role", String(64), default="admin"),
    Column("created_at", DateTime, default=datetime.now),
    Column("last_used", DateTime, nullable=True),
    Column("is_active", Boolean, default=True),
)

security_events_table = Table(
    "security_events", metadata,
    Column("id", String(64), primary_key=True),
    Column("tenant_id", String(64), nullable=False),
    Column("event_type", String(128), nullable=False),
    Column("data", JSON),
    Column("timestamp", DateTime, default=datetime.now),
)

audit_logs_table = Table(
    "audit_logs", metadata,
    Column("id", String(64), primary_key=True),
    Column("tenant_id", String(64), nullable=False),
    Column("user_id", String(128), nullable=True),
    Column("action", String(256), nullable=False),
    Column("details", JSON),
    Column("timestamp", DateTime, default=datetime.now),
)

webhooks_table = Table(
    "webhooks", metadata,
    Column("id", String(64), primary_key=True),
    Column("tenant_id", String(64), nullable=False),
    Column("url", String(1024), nullable=False),
    Column("events", JSON),
    Column("secret", String(512), nullable=True),
    Column("is_active", Boolean, default=True),
    Column("created_at", DateTime, default=datetime.now),
    Column("updated_at", DateTime, nullable=True),
    Column("last_triggered_at", DateTime, nullable=True),
    Column("failure_count", Integer, default=0),
)

alerts_table = Table(
    "alerts", metadata,
    Column("id", String(64), primary_key=True),
    Column("tenant_id", String(64), nullable=False),
    Column("type", String(128), nullable=False),
    Column("severity", String(32), default="medium"),
    Column("message", Text),
    Column("status", String(32), default="open"),
    Column("data", JSON),
    Column("created_at", DateTime, default=datetime.now),
    Column("updated_at", DateTime, nullable=True),
)

daily_stats_table = Table(
    "daily_stats", metadata,
    Column("id", String(64), primary_key=True),
    Column("tenant_id", String(64), nullable=False),
    Column("date", String(16), nullable=False),
    Column("events", Integer, default=0),
    Column("blocked", Integer, default=0),
    Column("allowed", Integer, default=0),
    Column("data", JSON),
)

agent_profiles_table = Table(
    "agent_profiles", metadata,
    Column("agent_id", String(128), primary_key=True),
    Column("tenant_id", String(64), nullable=False),
    Column("name", String(256)),
    Column("profile", JSON),
    Column("created_at", DateTime, default=datetime.now),
    Column("updated_at", DateTime, nullable=True),
)


class PostgresStorage(StorageBackend):
    def __init__(self, database_url: str):
        self.database_url = database_url
        self._engine = None
        self._session_factory = None
        self._initialized = False

    async def initialize(self) -> None:
        if self._initialized:
            return
        self._engine = create_async_engine(self.database_url, echo=False, pool_size=10, max_overflow=20)
        self._session_factory = async_sessionmaker(self._engine, class_=AsyncSession, expire_on_commit=False)
        async with self._engine.begin() as conn:
            await conn.run_sync(metadata.create_all)
        self._initialized = True
        logger.info("PostgreSQL storage initialized")

    async def close(self) -> None:
        if self._engine:
            await self._engine.dispose()
        self._initialized = False

    @asynccontextmanager
    async def _session(self):
        async with self._session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def create_tenant(self, tenant_id: str, name: str, config: Optional[Dict] = None) -> Dict:
        async with self._session() as session:
            result = await session.execute(
                tenants_table.select().where(tenants_table.c.tenant_id == tenant_id)
            )
            if result.scalar_one_or_none():
                raise ValueError(f"Tenant {tenant_id} already exists")
            await session.execute(
                tenants_table.insert().values(
                    tenant_id=tenant_id, name=name,
                    config=config or {}, status="active",
                    created_at=datetime.now()
                )
            )
            return {"tenant_id": tenant_id, "name": name, "config": config or {}, "status": "active"}

    async def get_tenant(self, tenant_id: str) -> Optional[Dict]:
        async with self._session() as session:
            result = await session.execute(
                tenants_table.select().where(tenants_table.c.tenant_id == tenant_id)
            )
            row = result.fetchone()
            if row:
                return dict(row._mapping)
            return None

    async def list_tenants(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        async with self._session() as session:
            result = await session.execute(
                tenants_table.select().limit(limit).offset(offset)
            )
            return [dict(r._mapping) for r in result.fetchall()]

    async def create_api_key(self, tenant_id: str, role: str = "admin") -> Dict:
        key_id = f"hst_{uuid.uuid4().hex[:8]}"
        secret = secrets.token_urlsafe(32)
        full_key = f"{key_id}_{secret}"
        import hashlib
        key_hash = hashlib.sha256(full_key.encode()).hexdigest()
        async with self._session() as session:
            await session.execute(
                api_keys_table.insert().values(
                    key_hash=key_hash, key_id=key_id,
                    tenant_id=tenant_id, role=role,
                    created_at=datetime.now(), is_active=True
                )
            )
            return {"key": full_key, "key_id": key_id, "tenant_id": tenant_id, "role": role}

    async def validate_api_key(self, api_key: str) -> Optional[Dict]:
        import hashlib
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        async with self._session() as session:
            result = await session.execute(
                api_keys_table.select().where(
                    api_keys_table.c.key_hash == key_hash
                ).where(api_keys_table.c.is_active == True)
            )
            row = result.fetchone()
            if row:
                data = dict(row._mapping)
                await session.execute(
                    api_keys_table.update().where(
                        api_keys_table.c.key_hash == key_hash
                    ).values(last_used=datetime.now())
                )
                return data
            return None

    async def revoke_api_key(self, api_key: str) -> bool:
        import hashlib
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        async with self._session() as session:
            result = await session.execute(
                api_keys_table.update().where(
                    api_keys_table.c.key_hash == key_hash
                ).values(is_active=False)
            )
            return result.rowcount > 0

    async def store_event(self, event_data: Dict) -> str:
        event_id = event_data.get("id", str(uuid.uuid4()))
        async with self._session() as session:
            await session.execute(
                security_events_table.insert().values(
                    id=event_id,
                    tenant_id=event_data.get("tenant_id", ""),
                    event_type=event_data.get("event_type", "unknown"),
                    data=event_data,
                    timestamp=datetime.now()
                )
            )
            return event_id

    async def get_events(self, tenant_id: Optional[str] = None, event_type: Optional[str] = None,
                         limit: int = 100, offset: int = 0) -> List[Dict]:
        async with self._session() as session:
            query = security_events_table.select()
            if tenant_id:
                query = query.where(security_events_table.c.tenant_id == tenant_id)
            if event_type:
                query = query.where(security_events_table.c.event_type == event_type)
            query = query.order_by(security_events_table.c.timestamp.desc()).limit(limit).offset(offset)
            result = await session.execute(query)
            return [dict(r._mapping) for r in result.fetchall()]

    async def count_events(self, tenant_id: str, hours: int = 24) -> int:
        from datetime import timedelta, timezone
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        async with self._session() as session:
            result = await session.execute(
                text("SELECT COUNT(*) FROM security_events WHERE tenant_id = :tid AND timestamp >= :cutoff"),
                {"tid": tenant_id, "cutoff": cutoff}
            )
            return result.scalar() or 0

    async def store_audit_log(self, audit_data: Dict) -> str:
        log_id = str(uuid.uuid4())
        async with self._session() as session:
            await session.execute(
                audit_logs_table.insert().values(
                    id=log_id,
                    tenant_id=audit_data.get("tenant_id", ""),
                    user_id=audit_data.get("user_id"),
                    action=audit_data.get("action", "unknown"),
                    details=audit_data,
                    timestamp=datetime.now()
                )
            )
            return log_id

    async def get_audit_logs(self, tenant_id: str, user_id: Optional[str] = None,
                             limit: int = 100) -> List[Dict]:
        async with self._session() as session:
            query = audit_logs_table.select().where(
                audit_logs_table.c.tenant_id == tenant_id
            )
            if user_id:
                query = query.where(audit_logs_table.c.user_id == user_id)
            query = query.order_by(audit_logs_table.c.timestamp.desc()).limit(limit)
            result = await session.execute(query)
            return [dict(r._mapping) for r in result.fetchall()]

    async def create_webhook(self, tenant_id: str, url: str, events: List[str],
                             secret: Optional[str] = None) -> Dict:
        webhook_id = f"wh_{uuid.uuid4().hex[:8]}"
        async with self._session() as session:
            await session.execute(
                webhooks_table.insert().values(
                    id=webhook_id, tenant_id=tenant_id, url=url,
                    events=events, secret=secret, is_active=True,
                    created_at=datetime.now(), failure_count=0
                )
            )
            return {"id": webhook_id, "tenant_id": tenant_id, "url": url,
                    "events": events, "is_active": True, "failure_count": 0}

    async def get_webhooks_for_tenant(self, tenant_id: str) -> List[Dict]:
        async with self._session() as session:
            result = await session.execute(
                webhooks_table.select().where(
                    webhooks_table.c.tenant_id == tenant_id
                ).where(webhooks_table.c.is_active == True)
            )
            return [dict(r._mapping) for r in result.fetchall()]

    async def update_webhook(self, webhook_id: str, updates: Dict) -> bool:
        async with self._session() as session:
            result = await session.execute(
                webhooks_table.update().where(
                    webhooks_table.c.id == webhook_id
                ).values(**updates, updated_at=datetime.now())
            )
            return result.rowcount > 0

    async def delete_webhook(self, webhook_id: str) -> bool:
        async with self._session() as session:
            result = await session.execute(
                webhooks_table.update().where(
                    webhooks_table.c.id == webhook_id
                ).values(is_active=False, updated_at=datetime.now())
            )
            return result.rowcount > 0

    async def create_agent_profile(self, agent_data: Dict) -> Dict:
        async with self._session() as session:
            await session.execute(
                agent_profiles_table.insert().values(
                    agent_id=agent_data["agent_id"],
                    tenant_id=agent_data.get("tenant_id", ""),
                    name=agent_data.get("name", ""),
                    profile=agent_data,
                    created_at=datetime.now()
                )
            )
            return agent_data

    async def get_agent_profile(self, agent_id: str) -> Optional[Dict]:
        async with self._session() as session:
            result = await session.execute(
                agent_profiles_table.select().where(
                    agent_profiles_table.c.agent_id == agent_id
                )
            )
            row = result.fetchone()
            if row:
                return dict(row._mapping)
            return None

    async def update_agent_profile(self, agent_id: str, updates: Dict) -> bool:
        async with self._session() as session:
            result = await session.execute(
                agent_profiles_table.update().where(
                    agent_profiles_table.c.agent_id == agent_id
                ).values(**updates, updated_at=datetime.now())
            )
            return result.rowcount > 0

    async def create_alert(self, alert_data: Dict) -> str:
        alert_id = str(uuid.uuid4())
        async with self._session() as session:
            await session.execute(
                alerts_table.insert().values(
                    id=alert_id,
                    tenant_id=alert_data.get("tenant_id", ""),
                    type=alert_data.get("type", "security"),
                    severity=alert_data.get("severity", "medium"),
                    message=alert_data.get("message", ""),
                    status="open",
                    data=alert_data,
                    created_at=datetime.now()
                )
            )
            return alert_id

    async def get_alerts(self, tenant_id: str, status: Optional[str] = None,
                         limit: int = 100) -> List[Dict]:
        async with self._session() as session:
            query = alerts_table.select().where(alerts_table.c.tenant_id == tenant_id)
            if status:
                query = query.where(alerts_table.c.status == status)
            query = query.order_by(alerts_table.c.created_at.desc()).limit(limit)
            result = await session.execute(query)
            return [dict(r._mapping) for r in result.fetchall()]

    async def update_alert(self, alert_id: str, updates: Dict) -> bool:
        async with self._session() as session:
            result = await session.execute(
                alerts_table.update().where(
                    alerts_table.c.id == alert_id
                ).values(**updates, updated_at=datetime.now())
            )
            return result.rowcount > 0

    async def get_daily_stats(self, tenant_id: str, date: datetime) -> Dict:
        date_str = date.strftime("%Y-%m-%d")
        async with self._session() as session:
            result = await session.execute(
                daily_stats_table.select().where(
                    daily_stats_table.c.tenant_id == tenant_id
                ).where(daily_stats_table.c.date == date_str)
            )
            row = result.fetchone()
            if row:
                return dict(row._mapping)
            return {"tenant_id": tenant_id, "date": date_str, "events": 0, "blocked": 0, "allowed": 0}

    async def update_daily_stats(self, tenant_id: str, date: datetime, new_stats: Dict) -> None:
        date_str = date.strftime("%Y-%m-%d")
        async with self._session() as session:
            result = await session.execute(
                daily_stats_table.update().where(
                    daily_stats_table.c.tenant_id == tenant_id
                ).where(daily_stats_table.c.date == date_str
                ).values(**new_stats)
            )
            if result.rowcount == 0:
                await session.execute(
                    daily_stats_table.insert().values(
                        id=str(uuid.uuid4()), tenant_id=tenant_id,
                        date=date_str, **new_stats
                    )
                )

    async def health_check(self) -> Dict:
        try:
            async with self._session() as session:
                await session.execute(text("SELECT 1"))
                return {"backend": "postgresql", "status": "healthy", "database_url": self.database_url}
        except Exception as e:
            return {"backend": "postgresql", "status": "unhealthy", "error": str(e)}