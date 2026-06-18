"""
Tests for Self-Learning Attack Memory
"""

import pytest
import json
from hestia.memory.attack_memory import AttackMemory, AttackRecord
from hestia.memory.pattern_analyzer import PatternAnalyzer
from hestia.memory.self_learner import SelfLearner
from hestia.memory.strategy_optimizer import StrategyOptimizer


class TestAttackMemory:
    def test_store_and_get(self):
        memory = AttackMemory()

        record = AttackRecord(
            id="test_001",
            prompt="Test attack",
            tool_used="shell",
            target="test",
            was_blocked=False,
            risk_score=0.5,
            decision="allow",
            response="OK",
            timestamp="2026-06-20T12:00:00",
        )

        memory.store(record)
        retrieved = memory.get("test_001")

        assert retrieved is not None
        assert retrieved.id == "test_001"
        assert retrieved.prompt == "Test attack"

    def test_get_similar(self):
        memory = AttackMemory()

        records = [
            AttackRecord(
                id=f"test_{i:03d}",
                prompt=f"Test prompt {i}",
                tool_used="shell",
                target="test",
                was_blocked=False,
                risk_score=0.5,
                decision="allow",
                response="OK",
                timestamp="2026-06-20T12:00:00",
            )
            for i in range(10)
        ]

        for record in records:
            memory.store(record)

        similar = memory.get_similar("Test prompt 5", limit=3)
        assert len(similar) >= 1

    def test_stats(self):
        memory = AttackMemory()

        for i in range(10):
            record = AttackRecord(
                id=f"test_{i:03d}",
                prompt=f"Test {i}",
                tool_used="shell",
                target="test",
                was_blocked=i % 2 == 0,
                risk_score=0.5,
                decision="block" if i % 2 == 0 else "allow",
                response="OK",
                timestamp="2026-06-20T12:00:00",
            )
            memory.store(record)

        stats = memory.get_stats()
        assert stats["total_attacks"] == 10
        assert stats["blocked"] == 5

    def test_record_serialization(self):
        record = AttackRecord(
            id="test_ser",
            prompt="Test",
            tool_used="shell",
            target="test",
            was_blocked=True,
            risk_score=0.8,
            decision="block",
            response="Blocked",
            timestamp="2026-06-20T12:00:00",
            context={"key": "value"},
            variants=["v1", "v2"],
        )

        d = record.to_dict()
        restored = AttackRecord.from_dict(d)
        assert restored.id == record.id
        assert restored.was_blocked == record.was_blocked
        assert len(restored.variants) == 2


class TestPatternAnalyzer:
    def test_analyze_records(self):
        memory = AttackMemory()
        analyzer = PatternAnalyzer()

        for i in range(6):
            record = AttackRecord(
                id=f"pa_{i:03d}",
                prompt=f"read file {i}" if i < 3 else f"delete file {i}",
                tool_used="shell" if i < 3 else "fs.write",
                target="test",
                was_blocked=i >= 3,
                risk_score=0.3 if i < 3 else 0.8,
                decision="allow" if i < 3 else "block",
                response="OK",
                timestamp="2026-06-20T12:00:00",
                success=i < 3,
            )
            memory.store(record)

        ids = memory.get_recent(limit=6)
        records = [memory.get(id) for id in ids]
        records = [r for r in records if r is not None]

        analysis = analyzer.analyze_records(records)
        assert analysis["total_records"] == 6
        assert "tool_analysis" in analysis

    def test_success_and_failure_patterns(self):
        memory = AttackMemory()
        analyzer = PatternAnalyzer()

        for i in range(5):
            record = AttackRecord(
                id=f"sp_{i:03d}",
                prompt=f"Successful attack {i}",
                tool_used="shell",
                target="test",
                was_blocked=False,
                risk_score=0.3,
                decision="allow",
                response="OK",
                timestamp="2026-06-20T12:00:00",
                success=True,
            )
            memory.store(record)

        ids = memory.get_recent(limit=5)
        records = [memory.get(id) for id in ids]
        records = [r for r in records if r is not None]

        success = analyzer.get_success_patterns(records)
        assert len(success) >= 1
        assert success[0]["success_rate"] > 0


class TestSelfLearner:
    def test_learn_from_attack(self):
        memory = AttackMemory()
        learner = SelfLearner(memory)

        record = AttackRecord(
            id="sl_001",
            prompt="Test attack",
            tool_used="shell",
            target="test",
            was_blocked=True,
            risk_score=0.9,
            decision="block",
            response="Blocked",
            timestamp="2026-06-20T12:00:00",
            variants=[],
        )

        memory.store(record)
        result = learner.learn_from_attack("sl_001")

        assert result["attack_id"] == "sl_001"
        assert "recommendations" in result
        assert len(result["recommendations"]) > 0

    def test_learn_from_attack_not_found(self):
        memory = AttackMemory()
        learner = SelfLearner(memory)

        result = learner.learn_from_attack("nonexistent")
        assert "error" in result

    def test_generate_improved_attack(self):
        memory = AttackMemory()
        learner = SelfLearner(memory)

        for i in range(5):
            record = AttackRecord(
                id=f"gi_{i:03d}",
                prompt=f"Successful attack {i}",
                tool_used="shell",
                target="test",
                was_blocked=False,
                risk_score=0.3,
                decision="allow",
                response="OK",
                timestamp="2026-06-20T12:00:00",
                success=True,
                variants=[f"Variant {i}"],
            )
            memory.store(record)

        improved = learner.generate_improved_attack("New attack", "shell")
        assert improved is not None

    def test_learning_summary(self):
        memory = AttackMemory()
        learner = SelfLearner(memory)

        record = AttackRecord(
            id="ls_001",
            prompt="Test",
            tool_used="shell",
            target="test",
            was_blocked=False,
            risk_score=0.3,
            decision="allow",
            response="OK",
            timestamp="2026-06-20T12:00:00",
            success=True,
        )
        memory.store(record)

        summary = learner.get_learning_summary()
        assert summary["learning_status"] == "active"
        assert summary["total_learned"] == 1


class TestStrategyOptimizer:
    def test_update_and_get_strategy(self):
        memory = AttackMemory()
        optimizer = StrategyOptimizer(memory)

        record = AttackRecord(
            id="so_001",
            prompt="Test attack",
            tool_used="shell",
            target="test",
            was_blocked=False,
            risk_score=0.5,
            decision="allow",
            response="OK",
            timestamp="2026-06-20T12:00:00",
            success=True,
        )

        optimizer.update(record)
        strategy = optimizer.get_best_strategy()

        assert "weights" in strategy
        assert "top_tools" in strategy

    def test_generate_next_action(self):
        memory = AttackMemory()
        optimizer = StrategyOptimizer(memory)

        for i in range(10):
            record = AttackRecord(
                id=f"na_{i:03d}",
                prompt=f"Test {i}",
                tool_used=f"tool_{i % 3}",
                target="test",
                was_blocked=i % 2 == 0,
                risk_score=0.5,
                decision="allow" if i % 2 == 0 else "block",
                response="OK",
                timestamp="2026-06-20T12:00:00",
                success=i % 2 == 0,
            )
            optimizer.update(record)

        action = optimizer.generate_next_action({})
        assert "strategy" in action
        assert "preferred_tool" in action
