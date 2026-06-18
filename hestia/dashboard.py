"""
Dashboard data aggregation for Hestia Shield.

Provides helper functions that aggregate security data from storage
for the dashboard API endpoints.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .storage_base import StorageBackend

logger = logging.getLogger(__name__)


def _event_data(event: Dict) -> Dict:
    """Extract the inner data dict from a stored event."""
    return event.get("data", event)


def _decision_data(event: Dict) -> Dict:
    """Extract the decision dict from a stored event."""
    data = _event_data(event)
    return data.get("decision", data.get("decision", {}) or {})


now_utc = lambda: datetime.now(timezone.utc)


async def get_summary(storage: StorageBackend, tenant_id: str) -> Dict[str, Any]:
    """Aggregate summary statistics for a tenant."""
    now = now_utc()

    events_24h = await storage.count_events(tenant_id, hours=24)
    events_7d = await storage.count_events(tenant_id, hours=168)

    recent_events = await storage.get_events(
        tenant_id=tenant_id,
        limit=200,
    )

    blocks = sum(
        1 for e in recent_events
        if _decision_data(e).get("decision") == "block"
    )
    total_decisions = len(recent_events)
    block_rate = round(blocks / total_decisions, 4) if total_decisions else 0.0

    agents = set()
    for e in recent_events:
        data = _event_data(e)
        agent = data.get("agent_id")
        if agent:
            agents.add(agent)
    agent_count = len(agents)

    alerts = await storage.get_alerts(tenant_id, status="open", limit=100)
    alert_count = len(alerts)

    today = now.date()
    daily = await storage.get_daily_stats(tenant_id, today)
    avg_latency = daily.get("avg_latency_ms", 0) if daily else 0

    federated_stats = {}
    from .decision_engine import DecisionEngine
    engine = DecisionEngine()
    if engine._federated_enabled and engine.federated_protocol:
        fed = engine.federated_protocol.get_stats()
        federated_stats = {
            "enabled": True,
            "contributions": fed.get("contribution_count", 0),
            "syncs": fed.get("sync_count", 0),
            "global_patterns": fed.get("global_intel", {}).get("total_patterns", 0),
            "unique_tenants": fed.get("aggregator", {}).get("unique_tenants", 0),
        }
    else:
        federated_stats = {"enabled": False}

    return {
        "tenant_id": tenant_id,
        "period_hours": 24,
        "total_requests": events_24h,
        "total_requests_7d": events_7d,
        "blocks": blocks,
        "block_rate": block_rate,
        "unique_agents": agent_count,
        "active_alerts": alert_count,
        "avg_latency_ms": avg_latency,
        "federated_learning": federated_stats,
    }


async def get_trends(
    storage: StorageBackend,
    tenant_id: str,
    hours: int = 24,
) -> Dict[str, Any]:
    """Build time-series trend data for requests and latency."""
    now = now_utc()

    events = await storage.get_events(
        tenant_id=tenant_id,
        limit=1000,
    )

    buckets: Dict[str, Dict] = {}
    for i in range(hours, -1, -1):
        ts = (now - timedelta(hours=i)).strftime("%Y-%m-%dT%H:00:00")
        buckets[ts] = {
            "timestamp": ts,
            "requests": 0,
            "blocks": 0,
            "avg_latency_ms": 0,
            "latencies": [],
        }

    for event in events:
        ts = event.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            bucket_key = dt.strftime("%Y-%m-%dT%H:00:00")
            if bucket_key in buckets:
                buckets[bucket_key]["requests"] += 1
                decision = _decision_data(event)
                if decision.get("decision") == "block":
                    buckets[bucket_key]["blocks"] += 1
                lat = decision.get("details", {}).get("latency_ms", 0)
                if lat:
                    buckets[bucket_key]["latencies"].append(lat)
        except (ValueError, AttributeError):
            continue

    series = []
    for bucket in buckets.values():
        latencies = bucket.pop("latencies", [])
        bucket["avg_latency_ms"] = round(
            sum(latencies) / len(latencies), 2
        ) if latencies else 0
        series.append(bucket)

    return {
        "tenant_id": tenant_id,
        "period_hours": hours,
        "series": series,
    }


async def get_recent_alerts(
    storage: StorageBackend,
    tenant_id: str,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    """Get the most recent alerts for a tenant."""
    alerts = await storage.get_alerts(tenant_id=tenant_id, limit=limit)
    return [
        {
            "id": a.get("id"),
            "severity": a.get("severity", "info"),
            "title": a.get("title", a.get("type", "Alert")),
            "message": a.get("message", ""),
            "status": a.get("status", "open"),
            "agent_id": a.get("agent_id", ""),
            "created_at": a.get("created_at", ""),
        }
        for a in alerts
    ]


async def get_policy_status(storage: StorageBackend, tenant_id: str) -> Dict[str, Any]:
    """Get active policy information for a tenant."""
    events = await storage.get_events(
        tenant_id=tenant_id,
        limit=500,
    )

    rules_triggered: Dict[str, int] = {}
    for event in events:
        details = _decision_data(event).get("details", {})
        rules = details.get("rules", []) or details.get("triggered_rules", [])
        if isinstance(rules, list):
            for rule in rules:
                name = rule if isinstance(rule, str) else rule.get("name", str(rule))
                rules_triggered[name] = rules_triggered.get(name, 0) + 1

    active_policies = [
        {"name": name, "triggered_count": count}
        for name, count in sorted(
            rules_triggered.items(), key=lambda x: x[1], reverse=True
        )
    ]

    return {
        "tenant_id": tenant_id,
        "total_policies_triggered": len(active_policies),
        "active_policies": active_policies,
    }
