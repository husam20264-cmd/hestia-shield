"""
Integration tests for Federated Learning in DecisionEngine pipeline.
"""

import os
import pytest
from unittest.mock import patch, MagicMock
from hestia.decision_engine import DecisionEngine
from hestia.models import Decision, DecisionType, RiskLevel, ToolCall


@pytest.fixture
def engine_with_federated():
    with patch.dict(os.environ, {
        "HESTIA_FEDERATED_ENABLED": "true",
        "HESTIA_TENANT_ID": "test_tenant",
        "HESTIA_FEDERATED_EPSILON": "1.0",
        "HESTIA_FEDERATED_CONTRIBUTION_INTERVAL": "0",
        "HESTIA_FEDERATED_SYNC_INTERVAL": "0",
    }):
        engine = DecisionEngine()
        yield engine


@pytest.fixture
def engine_without_federated():
    with patch.dict(os.environ, {
        "HESTIA_FEDERATED_ENABLED": "false",
    }):
        engine = DecisionEngine()
        yield engine


class TestFederatedInit:
    def test_federated_disabled_by_default(self):
        engine = DecisionEngine()
        assert not engine._federated_enabled

    def test_federated_enabled_when_env_set(self, engine_with_federated):
        assert engine_with_federated._federated_enabled
        assert engine_with_federated.federated_protocol is not None
        assert engine_with_federated.federated_encoder is not None

    def test_federated_stats_in_get_stats_when_enabled(self, engine_with_federated):
        stats = engine_with_federated.get_stats()
        assert "federated" in stats
        assert stats["federated"]["enabled"] is True
        assert stats["federated"]["global_pattern_matches"] == 0

    def test_federated_stats_not_in_get_stats_when_disabled(self, engine_without_federated):
        stats = engine_without_federated.get_stats()
        assert "federated" not in stats


class TestFederatedEvaluatePrompt:
    @pytest.mark.asyncio
    async def test_global_pattern_match_escalates_risk(self, engine_with_federated):
        high_risk_embedding = {
            "prompt_length": 0.5, "word_count": 0.3, "digit_ratio": 0.0,
            "uppercase_ratio": 0.0, "special_char_ratio": 0.0,
            "has_dangerous_keyword": 1.0, "high_risk_score": 0.95,
            "tool_critical": 0.0, "tool_write_category": 0.0,
            "is_production_env": 0.0, "has_arguments": 0.0,
            "was_blocked": 1.0, "risk_level_critical": 1.0,
            "risk_level_high": 0.0, "risk_level_medium": 0.0,
            "num_previous_blocks": 0.0,
        }
        engine_with_federated.federated_protocol.global_intel.ingest(
            embedding=high_risk_embedding,
            tool_category="shell",
            avg_risk_score=0.95,
            severity="critical",
        )
        decision = await engine_with_federated.evaluate_prompt(
            prompt="list files", user_id="usr_1"
        )
        assert decision.risk_score >= 0.9
        assert engine_with_federated._federated_matches == 1

    @pytest.mark.asyncio
    async def test_contribute_on_record(self, engine_with_federated):
        decision = Decision(
            decision=DecisionType.ALLOW,
            risk_score=0.1,
            reason="test",
            details={},
        )
        engine_with_federated._record_decision(decision, "test prompt")
        stats = engine_with_federated.federated_protocol.get_stats()
        assert stats["contribution_count"] >= 1


class TestFederatedEvaluateToolCall:
    @pytest.mark.asyncio
    async def test_matching_global_pattern_blocks_tool(self, engine_with_federated):
        critical_embedding = {
            "prompt_length": 0.0, "word_count": 0.0, "digit_ratio": 0.0,
            "uppercase_ratio": 0.0, "special_char_ratio": 0.0,
            "has_dangerous_keyword": 0.0, "high_risk_score": 0.85,
            "tool_critical": 1.0, "tool_write_category": 0.0,
            "is_production_env": 0.0, "has_arguments": 0.0,
            "was_blocked": 0.0, "risk_level_critical": 0.0,
            "risk_level_high": 1.0, "risk_level_medium": 0.0,
            "num_previous_blocks": 0.0,
        }
        engine_with_federated.federated_protocol.global_intel.ingest(
            embedding=critical_embedding,
            tool_category="execute",
            avg_risk_score=0.85,
            severity="high",
        )
        tool_call = ToolCall(
            name="read_file",
            category="read",
            target={"path": "/tmp"},
            arguments={},
            environment="development",
        )
        decision = await engine_with_federated.evaluate_tool_call(
            tool_call=tool_call, user_id="usr_1"
        )
        assert decision.decision == DecisionType.HUMAN_REVIEW
        assert "global threat pattern" in decision.reason.lower()
        assert engine_with_federated._federated_matches == 1


class TestFederatedAPIE:
    def test_federated_stats_endpoint(self, test_client, test_token):
        response = test_client.get(
            "/v1/federated/stats",
            headers={"Authorization": f"Bearer {test_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "federated_enabled" in data

    def test_federated_global_patterns_endpoint(self, test_client, test_token):
        response = test_client.get(
            "/v1/federated/global-patterns",
            headers={"Authorization": f"Bearer {test_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "patterns" in data

    def test_federated_sync_endpoint(self, test_client, test_token):
        response = test_client.post(
            "/v1/federated/sync",
            headers={"Authorization": f"Bearer {test_token}"}
        )
        assert response.status_code == 200
