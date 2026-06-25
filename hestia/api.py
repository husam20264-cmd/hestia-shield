"""
API for Hestia Shield v3.0.0
"""

import os
import logging
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Dict, List, Optional
from contextlib import asynccontextmanager

from .db import get_storage
from .auth import AuthManager
from .decision_engine import DecisionEngine
from .models import ToolCall, DecisionType
from .storage_base import StorageBackend
from .telemetry import setup_telemetry, instrument_fastapi, get_tracer, get_meter, shutdown_telemetry

logger = logging.getLogger(__name__)

tenants: Dict = {}
storage: StorageBackend = None
auth_manager: AuthManager = None

app = FastAPI(
    title="Hestia Shield API",
    version="3.0.0",
    description="Runtime Security for AI Agents",
)

security = HTTPBearer(auto_error=False)


def get_tenant(tenant_id: str):
    if tenant_id not in tenants:
        tenants[tenant_id] = DecisionEngine(
            rules_engine=None,
            classifier=None,
            attack_memory=None
        )
    return tenants[tenant_id]


async def verify_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
):
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing credentials")

    token = credentials.credentials
    payload = await auth_manager.validate_token(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    return payload


class EvaluatePromptRequest(BaseModel):
    prompt: str
    model_id: Optional[str] = None
    user_id: str
    context: Optional[Dict] = None


class EvaluateToolRequest(BaseModel):
    agent_id: str
    tool_call: Dict
    user_id: str
    context: Optional[Dict] = None


class TokenRequest(BaseModel):
    api_key: str


@app.get("/health")
async def health_check():
    health = await storage.health_check()
    return {"status": "healthy", "version": "1.1.0", "storage": health}


@app.post("/v1/token")
async def get_token(request: TokenRequest):
    key_data = await auth_manager.validate_api_key(request.api_key)

    if not key_data:
        raise HTTPException(status_code=401, detail="Invalid API key")

    token = auth_manager.create_token(
        key_data.get("tenant_id", "unknown"),
        key_data.get("role", "admin")
    )
    return {"token": token, "expires_in": 86400}


@app.post("/v1/decision/evaluate")
async def evaluate_prompt(
    request: EvaluatePromptRequest,
    auth: dict = Depends(verify_auth)
):
    tenant_id = auth["tenant_id"]
    engine = get_tenant(tenant_id)

    decision = await engine.evaluate_prompt(
        prompt=request.prompt,
        user_id=request.user_id,
        model_id=request.model_id,
        context=request.context
    )

    from .webhooks import queue_event
    await queue_event(tenant_id, {
        "tenant_id": tenant_id,
        "event_type": "prompt_evaluation",
        "decision": decision.to_dict()
    })

    return decision.to_dict()


@app.post("/v1/agent/tool-call/evaluate")
async def evaluate_tool_call(
    request: EvaluateToolRequest,
    auth: dict = Depends(verify_auth)
):
    tenant_id = auth["tenant_id"]
    engine = get_tenant(tenant_id)

    tool_call = ToolCall(
        name=request.tool_call.get("name", "unknown"),
        category=request.tool_call.get("category", "general"),
        target=request.tool_call.get("target", {}),
        arguments=request.tool_call.get("arguments", {})
    )

    decision = await engine.evaluate_tool_call(
        tool_call=tool_call,
        user_id=request.user_id,
        agent_id=request.agent_id
    )

    from .webhooks import queue_event
    await queue_event(tenant_id, {
        "tenant_id": tenant_id,
        "event_type": "tool_call_evaluation",
        "decision": decision.to_dict()
    })

    return decision.to_dict()


@app.get("/v1/stats")
async def get_stats(auth: dict = Depends(verify_auth)):
    tenant_id = auth["tenant_id"]
    engine = get_tenant(tenant_id)

    return {
        "tenant_id": tenant_id,
        "stats": engine.get_stats()
    }


@app.get("/v1/agents")
async def get_agents(auth: dict = Depends(verify_auth)):
    tenant_id = auth["tenant_id"]
    engine = get_tenant(tenant_id)

    if hasattr(engine, 'agent_monitor'):
        return {"agents": engine.agent_monitor.get_all_agents()}

    return {"agents": []}


# ── Dashboard Endpoints ─────────────────────────────────────────────

@app.get("/v1/dashboard/summary")
async def dashboard_summary(auth: dict = Depends(verify_auth)):
    from .dashboard import get_summary
    tenant_id = auth["tenant_id"]
    data = await get_summary(storage, tenant_id)
    return data


@app.get("/v1/dashboard/trends")
async def dashboard_trends(
    hours: int = 24,
    auth: dict = Depends(verify_auth),
):
    from .dashboard import get_trends
    tenant_id = auth["tenant_id"]
    data = await get_trends(storage, tenant_id, hours=hours)
    return data


@app.get("/v1/dashboard/recent-alerts")
async def dashboard_recent_alerts(
    limit: int = 20,
    auth: dict = Depends(verify_auth),
):
    from .dashboard import get_recent_alerts
    tenant_id = auth["tenant_id"]
    data = await get_recent_alerts(storage, tenant_id, limit=limit)
    return {"alerts": data}


@app.get("/v1/dashboard/policy-status")
async def dashboard_policy_status(auth: dict = Depends(verify_auth)):
    from .dashboard import get_policy_status
    tenant_id = auth["tenant_id"]
    data = await get_policy_status(storage, tenant_id)
    return data


@app.get("/dashboard")
async def dashboard_ui():
    """Serve the dashboard HTML page."""
    import os
    from fastapi.responses import FileResponse
    dashboard_path = os.path.join(
        os.path.dirname(__file__), "static", "dashboard.html"
    )
    if os.path.exists(dashboard_path):
        return FileResponse(dashboard_path, media_type="text/html")
    return {"error": "Dashboard UI not found"}


# ── Federated Learning Endpoints ──────────────────────────────────

_FEDERATED_CLIENTS: Dict[str, "UpdateProtocol"] = {}


def _get_federated(tenant_id: str):
    if tenant_id not in _FEDERATED_CLIENTS:
        from .decision_engine import DecisionEngine
        engine = get_tenant(tenant_id)
        if engine._federated_enabled and engine.federated_protocol:
            _FEDERATED_CLIENTS[tenant_id] = engine.federated_protocol
    return _FEDERATED_CLIENTS.get(tenant_id)


@app.get("/v1/federated/stats")
async def federated_stats(auth: dict = Depends(verify_auth)):
    tenant_id = auth["tenant_id"]
    protocol = _get_federated(tenant_id)
    if not protocol:
        return {"tenant_id": tenant_id, "federated_enabled": False}
    return {"tenant_id": tenant_id, "federated_enabled": True, "stats": protocol.get_stats()}


@app.get("/v1/federated/global-patterns")
async def federated_global_patterns(
    limit: int = 20,
    auth: dict = Depends(verify_auth),
):
    tenant_id = auth["tenant_id"]
    protocol = _get_federated(tenant_id)
    if not protocol:
        return {"patterns": []}
    return {"patterns": protocol.get_recent_global_patterns(limit=limit)}


@app.post("/v1/federated/sync")
async def federated_sync(
    auth: dict = Depends(verify_auth),
):
    tenant_id = auth["tenant_id"]
    protocol = _get_federated(tenant_id)
    if not protocol:
        return {"synced": False, "reason": "Federated learning not enabled"}
    results = protocol.sync(force=True)
    return {"synced": True, "results": results}


@app.on_event("startup")
async def startup_event():
    global storage, auth_manager

    setup_telemetry()
    instrument_fastapi(app)

    storage = get_storage()
    await storage.initialize()
    auth_manager = AuthManager(storage)

    from .queue import configure_queue
    configure_queue(storage)

    key_data = await storage.create_api_key("ten_demo", "admin")
    logger.info(f"Demo API key created: {key_data['key']}")


@app.on_event("shutdown")
async def shutdown_event():
    shutdown_telemetry()
    if storage and hasattr(storage, "close"):
        await storage.close()
    if storage and hasattr(storage, "close"):
        await storage.close()