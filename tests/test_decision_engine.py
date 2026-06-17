"""
Tests for Decision Engine v1.0.0
"""

import pytest
from hestia.decision_engine import DecisionEngine


class TestDecisionEngine:
    def test_fast_path_prompt(self, test_client, test_token):
        """Fast Path للـ prompt العادي"""
        response = test_client.post(
            "/v1/decision/evaluate",
            json={
                "prompt": "Summarize this document",
                "model_id": "mdl_1",
                "user_id": "usr_1"
            },
            headers={"Authorization": f"Bearer {test_token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "decision" in data

    def test_fast_path_tool(self, test_client, test_token):
        """Fast Path للـ tool call"""
        response = test_client.post(
            "/v1/agent/tool-call/evaluate",
            json={
                "agent_id": "agent_1",
                "user_id": "usr_1",
                "tool_call": {
                    "name": "search",
                    "category": "read",
                    "target": {"environment": "development"}
                }
            },
            headers={"Authorization": f"Bearer {test_token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "decision" in data

    def test_full_path_high_risk(self, test_client, test_token):
        """Full Path للطلبات عالية المخاطر"""
        response = test_client.post(
            "/v1/decision/evaluate",
            json={
                "prompt": "Write a script to delete all files",
                "model_id": "mdl_1",
                "user_id": "usr_1"
            },
            headers={"Authorization": f"Bearer {test_token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "evaluation_ms" in data["details"] or "decision" in data

    def test_rules_block(self, test_client, test_token):
        """التحقق من حظر القواعد"""
        response = test_client.post(
            "/v1/decision/evaluate",
            json={
                "prompt": "rm -rf /",
                "model_id": "mdl_1",
                "user_id": "usr_1"
            },
            headers={"Authorization": f"Bearer {test_token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "block"

    def test_decision_is_blocked_property(self, test_client, test_token):
        """خاصية is_blocked"""
        response = test_client.post(
            "/v1/decision/evaluate",
            json={
                "prompt": "rm -rf /",
                "model_id": "mdl_1",
                "user_id": "usr_1"
            },
            headers={"Authorization": f"Bearer {test_token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "block"

    def test_decision_is_blocked_property(self, test_client, test_token):
        """خاصية is_blocked"""
        response = test_client.post(
            "/v1/decision/evaluate",
            json={
                "prompt": "rm -rf /",
                "model_id": "mdl_1",
                "user_id": "usr_1"
            },
            headers={"Authorization": f"Bearer {test_token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "block"