"""
Core tests for Hestia Shield v1.1.0
"""

import pytest
from hestia.models import Decision, DecisionType, RiskLevel


class TestModels:
    def test_decision_allow(self):
        decision = Decision(
            decision=DecisionType.ALLOW,
            risk_score=0.1,
            reason="Test"
        )
        assert decision.allowed is True
        assert decision.is_blocked is False

    def test_decision_block(self):
        decision = Decision(
            decision=DecisionType.BLOCK,
            risk_score=0.9,
            reason="Test"
        )
        assert decision.allowed is False
        assert decision.is_blocked is True

    def test_decision_is_blocked_with_terminate(self):
        decision = Decision(
            decision=DecisionType.TERMINATE_SESSION,
            risk_score=0.9,
            reason="Session terminated"
        )
        assert decision.is_blocked is True

    def test_decision_to_dict(self):
        decision = Decision(
            decision=DecisionType.ALLOW,
            risk_score=0.1,
            reason="Test",
            details={"key": "value"}
        )
        d = decision.to_dict()
        assert d["decision"] == "allow"
        assert d["risk_score"] == 0.1
        assert d["details"]["key"] == "value"

    def test_risk_level_enum(self):
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"


class TestRulesEngine:
    def test_rules_evaluate_block(self):
        from hestia.rules_engine import RulesEngine, Rule

        rules = RulesEngine([
            Rule(
                id="rule_1",
                name="Block dangerous",
                type="block_keywords",
                conditions={"keywords": ["rm -rf"]},
                action=DecisionType.BLOCK
            )
        ])

        decision = rules.evaluate({"text": "rm -rf /"})
        assert decision is not None
        assert decision.decision == DecisionType.BLOCK

    def test_rules_no_match(self):
        from hestia.rules_engine import RulesEngine, Rule

        rules = RulesEngine([
            Rule(
                id="rule_1",
                name="Block dangerous",
                type="block_keywords",
                conditions={"keywords": ["dangerous"]},
                action=DecisionType.BLOCK
            )
        ])

        decision = rules.evaluate({"text": "safe request"})
        assert decision is None

    def test_rules_by_priority(self):
        from hestia.rules_engine import RulesEngine, Rule

        rules = RulesEngine([
            Rule(id="low", name="Low", type="block_keywords",
                 conditions={"keywords": ["test"]}, action=DecisionType.ALLOW, priority=1),
            Rule(id="high", name="High", type="block_keywords",
                 conditions={"keywords": ["test"]}, action=DecisionType.BLOCK, priority=100),
        ])

        decision = rules.evaluate({"text": "test request"})
        assert decision.decision == DecisionType.BLOCK


class TestClassifier:
    def test_classifier_low_risk(self):
        from hestia.classifier import TextClassifier

        classifier = TextClassifier()

        risk, score, triggered = classifier.classify("Summarize this")
        assert risk == RiskLevel.LOW

    def test_classifier_critical_risk(self):
        from hestia.classifier import TextClassifier

        classifier = TextClassifier()
        risk, score, triggered = classifier.classify("delete all files")
        assert risk == RiskLevel.CRITICAL

    def test_classifier_high_risk(self):
        from hestia.classifier import TextClassifier

        classifier = TextClassifier()
        risk, score, triggered = classifier.classify("exploit vulnerability")
        assert risk == RiskLevel.HIGH


class TestStorage:
    @pytest.mark.asyncio
    async def test_create_tenant(self, test_storage):
        await test_storage.initialize()
        tenant = await test_storage.create_tenant("ten_1", "Test Tenant")
        assert tenant["tenant_id"] == "ten_1"

    @pytest.mark.asyncio
    async def test_duplicate_tenant(self, test_storage):
        await test_storage.initialize()
        await test_storage.create_tenant("ten_1", "Test")
        with pytest.raises(ValueError):
            await test_storage.create_tenant("ten_1", "Duplicate")

    @pytest.mark.asyncio
    async def test_api_key_flow(self, test_storage):
        await test_storage.initialize()
        key_data = await test_storage.create_api_key("ten_1", "admin")
        assert "key" in key_data

        validated = await test_storage.validate_api_key(key_data["key"])
        assert validated is not None
        assert validated["tenant_id"] == "ten_1"

    @pytest.mark.asyncio
    async def test_store_and_get_events(self, test_storage):
        await test_storage.initialize()
        event_id = await test_storage.store_event({
            "tenant_id": "ten_1",
            "event_type": "test",
            "data": "hello"
        })
        assert event_id is not None

        events = await test_storage.get_events(tenant_id="ten_1")
        assert len(events) >= 1

    @pytest.mark.asyncio
    async def test_health_check(self, test_storage):
        await test_storage.initialize()
        health = await test_storage.health_check()
        assert health["status"] == "healthy"


class TestAPI:
    def test_health_check(self, test_client):
        response = test_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_get_token(self, test_storage, test_client):
        import asyncio
        key_data = asyncio.run(test_storage.create_api_key("ten_test", "admin"))
        response = test_client.post(
            "/v1/token",
            json={"api_key": key_data["key"]}
        )
        assert response.status_code == 200
        assert "token" in response.json()

    def test_auth_required(self, test_client):
        response = test_client.post(
            "/v1/decision/evaluate",
            json={"prompt": "test"}
        )
        assert response.status_code == 401

    def test_invalid_token(self, test_client):
        response = test_client.post(
            "/v1/decision/evaluate",
            json={"prompt": "test", "model_id": "mdl_1", "user_id": "usr_1"},
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401

    def test_stats_endpoint(self, test_client, test_token):
        response = test_client.get(
            "/v1/stats",
            headers={"Authorization": f"Bearer {test_token}"}
        )
        assert response.status_code == 200
        assert "stats" in response.json()