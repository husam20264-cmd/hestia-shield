"""
Tests for Hestia Shield — Dashboard
"""

import pytest

from hestia.dashboard import get_summary, get_trends, get_recent_alerts, get_policy_status


class TestDashboardSummary:
    """Tests for dashboard summary aggregation."""

    @pytest.mark.asyncio
    async def test_summary_empty(self, test_storage):
        data = await get_summary(test_storage, "ten_test")
        assert data["tenant_id"] == "ten_test"
        assert data["total_requests"] == 0
        assert data["blocks"] == 0
        assert data["unique_agents"] == 0
        assert data["active_alerts"] == 0

    @pytest.mark.asyncio
    async def test_summary_with_events(self, test_storage):
        for i in range(5):
            await test_storage.store_event({
                "tenant_id": "ten_test",
                "event_type": "prompt_evaluation",
                "decision": {"decision": "allow", "risk_score": 0.1, "reason": "Safe"},
                "agent_id": "agent_1",
            })
        await test_storage.store_event({
            "tenant_id": "ten_test",
            "event_type": "tool_call_evaluation",
            "decision": {"decision": "block", "risk_score": 0.9, "reason": "Blocked"},
            "agent_id": "agent_2",
        })

        data = await get_summary(test_storage, "ten_test")
        assert data["total_requests"] == 6
        assert data["blocks"] == 1
        assert data["unique_agents"] == 2

    @pytest.mark.asyncio
    async def test_summary_with_alerts(self, test_storage):
        await test_storage.create_alert({
            "tenant_id": "ten_test",
            "severity": "high",
            "title": "Test alert",
        })
        data = await get_summary(test_storage, "ten_test")
        assert data["active_alerts"] == 1


class TestDashboardTrends:
    """Tests for trends aggregation."""

    @pytest.mark.asyncio
    async def test_trends_empty(self, test_storage):
        data = await get_trends(test_storage, "ten_test", hours=1)
        assert data["period_hours"] == 1
        assert len(data["series"]) == 2  # hours=1 gives 2 buckets (past hour + current)

    @pytest.mark.asyncio
    async def test_trends_with_events(self, test_storage):
        await test_storage.store_event({
            "tenant_id": "ten_test",
            "event_type": "prompt_evaluation",
            "decision": {"decision": "allow", "risk_score": 0.1, "reason": "Safe", "details": {"latency_ms": 5}},
        })
        data = await get_trends(test_storage, "ten_test", hours=1)
        total_requests = sum(s["requests"] for s in data["series"])
        assert total_requests >= 1


class TestDashboardAlerts:
    """Tests for recent alerts."""

    @pytest.mark.asyncio
    async def test_alerts_empty(self, test_storage):
        alerts = await get_recent_alerts(test_storage, "ten_test")
        assert alerts == []

    @pytest.mark.asyncio
    async def test_alerts_with_data(self, test_storage):
        await test_storage.create_alert({
            "tenant_id": "ten_test",
            "severity": "critical",
            "title": "Critical alert",
            "message": "Something bad happened",
            "agent_id": "agent_1",
        })
        alerts = await get_recent_alerts(test_storage, "ten_test")
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "critical"
        assert alerts[0]["title"] == "Critical alert"
        assert alerts[0]["agent_id"] == "agent_1"


class TestDashboardPolicy:
    """Tests for policy status."""

    @pytest.mark.asyncio
    async def test_policy_empty(self, test_storage):
        data = await get_policy_status(test_storage, "ten_test")
        assert data["total_policies_triggered"] == 0

    @pytest.mark.asyncio
    async def test_policy_with_rules_triggered(self, test_storage):
        await test_storage.store_event({
            "tenant_id": "ten_test",
            "event_type": "prompt_evaluation",
            "decision": {
                "decision": "block",
                "risk_score": 0.9,
                "reason": "Rule triggered",
                "details": {"rules": ["block_shell_commands", "block_sensitive_files"]},
            },
        })
        data = await get_policy_status(test_storage, "ten_test")
        assert data["total_policies_triggered"] >= 2


class TestDashboardAPI:
    """Tests for dashboard API endpoints."""

    def test_dashboard_auth_required(self, test_client):
        response = test_client.get("/v1/dashboard/summary")
        assert response.status_code == 401

        response = test_client.get("/v1/dashboard/trends")
        assert response.status_code == 401

        response = test_client.get("/v1/dashboard/recent-alerts")
        assert response.status_code == 401

        response = test_client.get("/v1/dashboard/policy-status")
        assert response.status_code == 401

    def test_dashboard_summary_endpoint(self, test_client, test_token):
        response = test_client.get(
            "/v1/dashboard/summary",
            headers={"Authorization": f"Bearer {test_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "tenant_id" in data
        assert "total_requests" in data
        assert "blocks" in data

    def test_dashboard_trends_endpoint(self, test_client, test_token):
        response = test_client.get(
            "/v1/dashboard/trends?hours=6",
            headers={"Authorization": f"Bearer {test_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "series" in data
        assert data["period_hours"] == 6

    def test_dashboard_alerts_endpoint(self, test_client, test_token):
        response = test_client.get(
            "/v1/dashboard/recent-alerts",
            headers={"Authorization": f"Bearer {test_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data

    def test_dashboard_policy_endpoint(self, test_client, test_token):
        response = test_client.get(
            "/v1/dashboard/policy-status",
            headers={"Authorization": f"Bearer {test_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "active_policies" in data

    def test_dashboard_all_endpoints_with_invalid_token(self, test_client):
        headers = {"Authorization": "Bearer invalid_token"}
        for path in ["/v1/dashboard/summary", "/v1/dashboard/trends",
                     "/v1/dashboard/recent-alerts", "/v1/dashboard/policy-status"]:
            response = test_client.get(path, headers=headers)
            assert response.status_code == 401, f"{path} should reject invalid token"
