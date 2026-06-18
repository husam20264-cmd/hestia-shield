"""
Tests for Adaptive Policy Generation
"""

import pytest
from hestia.memory.attack_memory import AttackMemory, AttackRecord
from hestia.memory.self_learner import SelfLearner
from hestia.policy.adaptive_generator import (
    AdaptivePolicyGenerator,
    PolicyApplier,
    GeneratedPolicy,
)
from hestia.rules_engine import RulesEngine
from hestia.models import Rule, DecisionType


class TestAdaptivePolicyGenerator:
    def test_init(self):
        memory = AttackMemory()
        generator = AdaptivePolicyGenerator(memory)
        assert generator.memory == memory
        assert generator.min_samples == 5
        assert generator.block_threshold == 0.85
        assert generator.review_threshold == 0.65

    def test_generate_no_data(self):
        memory = AttackMemory()
        generator = AdaptivePolicyGenerator(memory)
        policy = generator.generate(limit=10)
        assert policy is not None
        assert policy.policy_id.startswith("policy_")
        assert isinstance(policy.rules, list)
        assert policy.confidence == 0.1

    def test_generate_with_blocked_attacks(self):
        memory = AttackMemory()
        generator = AdaptivePolicyGenerator(memory, min_samples=3)

        for i in range(10):
            record = AttackRecord(
                id=f"test_block_{i:03d}",
                prompt=f"delete all files and destroy database {i}" if i < 5 else f"normal request {i}",
                tool_used="shell",
                target="filesystem",
                was_blocked=i < 5,
                risk_score=0.9 if i < 5 else 0.2,
                decision="block" if i < 5 else "allow",
                response="Blocked" if i < 5 else "OK",
                timestamp="2026-06-20T12:00:00",
                success=i >= 5,
            )
            memory.store(record)

        policy = generator.generate(limit=10)
        assert policy is not None
        assert policy.metadata["records_analyzed"] >= 10
        assert policy.confidence > 0

    def test_generate_tool_restrictions(self):
        memory = AttackMemory()
        generator = AdaptivePolicyGenerator(memory, min_samples=3, block_threshold=0.6)

        for i in range(15):
            tool = "dangerous_tool" if i < 10 else "safe_tool"
            record = AttackRecord(
                id=f"test_tool_{i:03d}",
                prompt=f"Execute command {i}",
                tool_used=tool,
                target="system",
                was_blocked=i < 10,
                risk_score=0.8 if i < 10 else 0.1,
                decision="block" if i < 10 else "allow",
                response="Blocked" if i < 10 else "OK",
                timestamp="2026-06-20T12:00:00",
                success=i >= 10,
            )
            memory.store(record)

        policy = generator.generate(limit=15)
        assert "dangerous_tool" in policy.tool_restrictions
        assert policy.tool_restrictions["dangerous_tool"] in ["blocked", "requires_review", "high_risk_monitor"]

    def test_compute_risk_thresholds(self):
        memory = AttackMemory()
        generator = AdaptivePolicyGenerator(memory)

        for i in range(10):
            record = AttackRecord(
                id=f"test_risk_{i:03d}",
                prompt=f"Test {i}",
                tool_used="shell",
                target="test",
                was_blocked=i < 5,
                risk_score=0.9 if i < 5 else 0.2,
                decision="block" if i < 5 else "allow",
                response="OK",
                timestamp="2026-06-20T12:00:00",
                success=i >= 5,
            )
            memory.store(record)

        policy = generator.generate(limit=10)
        assert "block" in policy.risk_thresholds
        assert "human_review" in policy.risk_thresholds
        assert 0.5 <= policy.risk_thresholds["block"] <= 0.99
        assert 0.3 <= policy.risk_thresholds["human_review"] <= 0.8

    def test_generate_from_lessons(self):
        memory = AttackMemory()
        generator = AdaptivePolicyGenerator(memory)

        lessons = {
            "overall_success_rate": 0.25,
            "failure_patterns": [
                {"pattern": "shell:exfil,steal,dump", "failure_rate": 0.85},
                {"pattern": "fs.write:delete,modify", "failure_rate": 0.75},
            ],
            "worst_tools": [
                {"tool": "dangerous_tool", "success_rate": 0.15, "total": 10},
            ],
        }

        policy_update = generator.generate_from_lessons(lessons)
        assert "new_block_keywords" in policy_update
        assert "tool_restrictions" in policy_update
        assert "risk_thresholds" in policy_update
        assert "suggested_actions" in policy_update
        assert policy_update["tool_restrictions"].get("dangerous_tool") == "human_review"
        assert policy_update["risk_thresholds"].get("block") == 0.75

    def test_get_stats(self):
        memory = AttackMemory()
        generator = AdaptivePolicyGenerator(memory)
        stats = generator.get_stats()
        assert "generation_count" in stats
        assert "min_samples" in stats
        assert stats["generation_count"] == 0


class TestPolicyApplier:
    def test_init(self):
        rules_engine = RulesEngine()
        applier = PolicyApplier(rules_engine)
        assert applier.rules_engine == rules_engine
        assert applier.auto_apply is False
        assert applier.dry_run is False

    def test_apply_dry_run(self):
        rules_engine = RulesEngine()
        applier = PolicyApplier(rules_engine, dry_run=True)

        policy = GeneratedPolicy(
            policy_id="test_policy",
            rules=[
                Rule(
                    id="test_rule",
                    name="Test Rule",
                    type="block_keywords",
                    conditions={"keywords": ["test"]},
                    action=DecisionType.BLOCK,
                    priority=5,
                )
            ],
            risk_thresholds={"block": 0.8},
            tool_restrictions={},
            confidence=0.7,
            source="test",
            timestamp="2026-06-20T12:00:00",
        )

        result = applier.apply(policy)
        assert result["status"] == "dry_run"
        assert len(applier.pending_policies) == 1

    def test_apply_pending_approval(self):
        rules_engine = RulesEngine()
        applier = PolicyApplier(rules_engine, auto_apply=False)

        policy = GeneratedPolicy(
            policy_id="test_policy",
            rules=[
                Rule(
                    id="test_rule",
                    name="Test Rule",
                    type="block_keywords",
                    conditions={"keywords": ["test"]},
                    action=DecisionType.BLOCK,
                    priority=5,
                )
            ],
            risk_thresholds={"block": 0.8},
            tool_restrictions={},
            confidence=0.7,
            source="test",
            timestamp="2026-06-20T12:00:00",
        )

        result = applier.apply(policy)
        assert result["status"] == "pending_approval"
        assert len(applier.pending_policies) == 1

    def test_apply_auto(self):
        rules_engine = RulesEngine()
        applier = PolicyApplier(rules_engine, auto_apply=True)

        policy = GeneratedPolicy(
            policy_id="test_policy",
            rules=[
                Rule(
                    id="test_rule",
                    name="Test Rule",
                    type="block_keywords",
                    conditions={"keywords": ["test"]},
                    action=DecisionType.BLOCK,
                    priority=5,
                )
            ],
            risk_thresholds={"block": 0.8},
            tool_restrictions={},
            confidence=0.7,
            source="test",
            timestamp="2026-06-20T12:00:00",
        )

        result = applier.apply(policy)
        assert result["status"] == "applied"
        assert result["rules_applied"] == 1
        assert len(applier.applied_policies) == 1

    def test_approve_pending(self):
        rules_engine = RulesEngine()
        applier = PolicyApplier(rules_engine, auto_apply=False)

        policy = GeneratedPolicy(
            policy_id="test_policy",
            rules=[
                Rule(
                    id="test_rule",
                    name="Test Rule",
                    type="block_keywords",
                    conditions={"keywords": ["test"]},
                    action=DecisionType.BLOCK,
                    priority=5,
                )
            ],
            risk_thresholds={"block": 0.8},
            tool_restrictions={},
            confidence=0.7,
            source="test",
            timestamp="2026-06-20T12:00:00",
        )

        applier.apply(policy)
        result = applier.approve_pending("test_policy")
        assert result["status"] == "applied"
        assert len(applier.pending_policies) == 0
        assert len(applier.applied_policies) == 1

    def test_reject_pending(self):
        rules_engine = RulesEngine()
        applier = PolicyApplier(rules_engine, auto_apply=False)

        policy = GeneratedPolicy(
            policy_id="test_policy",
            rules=[
                Rule(
                    id="test_rule",
                    name="Test Rule",
                    type="block_keywords",
                    conditions={"keywords": ["test"]},
                    action=DecisionType.BLOCK,
                    priority=5,
                )
            ],
            risk_thresholds={},
            tool_restrictions={},
            confidence=0.7,
            source="test",
            timestamp="2026-06-20T12:00:00",
        )

        applier.apply(policy)
        result = applier.reject_pending("test_policy")
        assert result["status"] == "rejected"
        assert len(applier.pending_policies) == 0

    def test_get_pending_and_applied(self):
        rules_engine = RulesEngine()
        applier = PolicyApplier(rules_engine, auto_apply=False)

        rule = Rule(
            id="test_rule",
            name="Test Rule",
            type="block_keywords",
            conditions={"keywords": ["test"]},
            action=DecisionType.BLOCK,
            priority=5,
        )

        policy1 = GeneratedPolicy(
            policy_id="policy_1",
            rules=[rule],
            risk_thresholds={},
            tool_restrictions={},
            confidence=0.7,
            source="test",
            timestamp="2026-06-20T12:00:00",
        )

        policy2 = GeneratedPolicy(
            policy_id="policy_2",
            rules=[rule],
            risk_thresholds={},
            tool_restrictions={},
            confidence=0.8,
            source="test",
            timestamp="2026-06-20T12:00:00",
        )

        applier.apply(policy1)
        applier.apply(policy2)

        pending = applier.get_pending()
        assert len(pending) == 2

        applier.approve_pending("policy_1")
        pending = applier.get_pending()
        assert len(pending) == 1

        applied = applier.get_applied()
        assert len(applied) == 1

    def test_get_stats(self):
        rules_engine = RulesEngine()
        applier = PolicyApplier(rules_engine, auto_apply=False, dry_run=True)
        stats = applier.get_stats()
        assert stats["auto_apply"] is False
        assert stats["dry_run"] is True
        assert "pending_count" in stats
        assert "applied_count" in stats


class TestSelfLearnerWithPolicyGenerator:
    def test_self_learner_with_policy_generator(self):
        memory = AttackMemory()
        generator = AdaptivePolicyGenerator(memory)
        learner = SelfLearner(memory, policy_generator=generator)

        for i in range(10):
            record = AttackRecord(
                id=f"sl_test_{i:03d}",
                prompt=f"Test attack {i}",
                tool_used="shell",
                target="test",
                was_blocked=i < 5,
                risk_score=0.8 if i < 5 else 0.2,
                decision="block" if i < 5 else "allow",
                response="OK",
                timestamp="2026-06-20T12:00:00",
                success=i >= 5,
            )
            memory.store(record)

        result = learner.learn_from_history(limit=10)
        assert "lessons" in result
        assert "recommendations" in result

    def test_self_learner_update_strategy_calls_policy_generator(self):
        memory = AttackMemory()
        generator = AdaptivePolicyGenerator(memory)
        learner = SelfLearner(memory, policy_generator=generator)

        lessons = {
            "overall_success_rate": 0.2,
            "failure_patterns": [],
            "worst_tools": [],
        }

        learner._update_strategy(lessons)
        assert learner.learning_rate > 0.1


class TestIntegration:
    def test_full_policy_cycle(self):
        memory = AttackMemory()
        generator = AdaptivePolicyGenerator(memory, min_samples=3)
        rules_engine = RulesEngine()
        applier = PolicyApplier(rules_engine, auto_apply=False)

        for i in range(15):
            tool = "dangerous_tool" if i < 10 else "safe_tool"
            record = AttackRecord(
                id=f"cycle_{i:03d}",
                prompt=f"Execute dangerous command {i}" if i < 10 else f"Safe operation {i}",
                tool_used=tool,
                target="system",
                was_blocked=i < 10,
                risk_score=0.85 if i < 10 else 0.15,
                decision="block" if i < 10 else "allow",
                response="OK",
                timestamp="2026-06-20T12:00:00",
                success=i >= 10,
            )
            memory.store(record)

        policy = generator.generate(limit=15)
        assert policy.confidence > 0
        assert policy.metadata["records_analyzed"] == 15

        result = applier.apply(policy)
        assert result["status"] == "pending_approval"

        if policy.rules:
            approve_result = applier.approve_pending(policy.policy_id)
            assert approve_result["status"] == "applied"