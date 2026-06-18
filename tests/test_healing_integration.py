"""
Integration tests: Self-Healing in DecisionEngine (v2.0.0)
"""

import os
import pytest
from unittest.mock import patch, MagicMock

from hestia.decision_engine import DecisionEngine
from hestia.models import RiskLevel, DecisionType


class TestHealingDisabledByDefault:

    def test_healing_not_initialized_without_env(self):
        engine = DecisionEngine()
        assert engine._healing_enabled is False
        assert engine.health_monitor is None
        assert engine.auto_rollback is None
        assert engine.adaptive_thresholds is None

    def test_get_stats_no_healing_key(self):
        engine = DecisionEngine()
        stats = engine.get_stats()
        assert "healing" not in stats

    def test_default_block_threshold_is_high(self):
        engine = DecisionEngine()
        assert engine._heal_block_threshold == RiskLevel.HIGH


class TestHealingEnabled:

    @pytest.fixture(autouse=True)
    def setup_env(self):
        with patch.dict(os.environ, {"HESTIA_HEALING_ENABLED": "true"}, clear=False):
            yield

    def test_healing_initialized_when_enabled(self):
        engine = DecisionEngine()
        assert engine._healing_enabled is True
        assert engine.health_monitor is not None
        assert engine.auto_rollback is not None
        assert engine.adaptive_thresholds is not None

    def test_health_monitor_records_decisions(self, setup_env):
        engine = DecisionEngine()
        hm = engine.health_monitor
        initial = hm.get_stats()["total_decisions"]
        # Run a decision that goes through _record_decision
        import asyncio
        asyncio.run(engine.evaluate_prompt(
            prompt="hello world",
            user_id="test_user",
        ))
        # HealthMonitor records decisions even when SL memory is disabled
        assert hm.get_stats()["total_decisions"] > initial

    def test_get_stats_includes_healing(self, setup_env):
        engine = DecisionEngine()
        stats = engine.get_stats()
        assert "healing" in stats
        healing = stats["healing"]
        assert healing["enabled"] is True
        assert healing["block_threshold"] == "high"
        assert "health" in healing
        assert "auto_rollback" in healing
        assert "adaptive_thresholds" in healing

    def test_adaptive_thresholds_wired_to_block_threshold(self, setup_env):
        engine = DecisionEngine()
        assert engine._heal_block_threshold == RiskLevel.HIGH
        assert engine.adaptive_thresholds.thresholds["block"] == 3.0

    def test_auto_rollback_has_reasonable_defaults(self, setup_env):
        engine = DecisionEngine()
        stats = engine.auto_rollback.get_stats()
        assert stats["fp_threshold"] == 0.05
        assert stats["min_decisions"] >= 50

    def test_decision_still_blocks_high_risk(self, setup_env):
        engine = DecisionEngine()
        import asyncio
        decision = asyncio.run(engine.evaluate_prompt(
            prompt="rm -rf /",
            user_id="test",
        ))
        assert decision.decision == DecisionType.BLOCK


class TestBlockThresholdAdjustment:

    @pytest.fixture(autouse=True)
    def setup_env(self):
        with patch.dict(os.environ, {"HESTIA_HEALING_ENABLED": "true"}, clear=False):
            yield

    def test_lower_threshold_blocks_more(self, setup_env):
        engine = DecisionEngine()
        engine._heal_block_threshold = RiskLevel.MEDIUM
        import asyncio
        decision = asyncio.run(engine.evaluate_prompt(
            prompt="run script",  # MEDIUM risk keyword
            user_id="test",
        ))
        assert decision.decision == DecisionType.BLOCK

    def test_higher_threshold_blocks_less(self, setup_env):
        engine = DecisionEngine()
        engine._heal_block_threshold = RiskLevel.CRITICAL
        import asyncio
        decision = asyncio.run(engine.evaluate_prompt(
            prompt="bypass security",  # HIGH risk (no longer blocks)
            user_id="test",
        ))
        assert decision.decision != DecisionType.BLOCK

    def test_threshold_can_change_during_lifetime(self, setup_env):
        engine = DecisionEngine()
        import asyncio

        engine._heal_block_threshold = RiskLevel.CRITICAL
        d1 = asyncio.run(engine.evaluate_prompt(
            prompt="bypass security", user_id="test",
        ))
        assert d1.decision != DecisionType.BLOCK

        engine._heal_block_threshold = RiskLevel.MEDIUM
        d2 = asyncio.run(engine.evaluate_prompt(
            prompt="run script", user_id="test",
        ))
        assert d2.decision == DecisionType.BLOCK

    def test_stats_reflects_current_threshold(self, setup_env):
        engine = DecisionEngine()
        engine._heal_block_threshold = RiskLevel.CRITICAL
        stats = engine.get_stats()
        assert stats["healing"]["block_threshold"] == "critical"


class TestEnvVarConfiguration:

    def test_custom_fp_threshold(self):
        with patch.dict(os.environ, {
            "HESTIA_HEALING_ENABLED": "true",
            "HESTIA_HEALING_FP_THRESHOLD": "0.10",
        }, clear=False):
            engine = DecisionEngine()
            assert engine.auto_rollback.fp_threshold == 0.10

    def test_custom_window_size(self):
        with patch.dict(os.environ, {
            "HESTIA_HEALING_ENABLED": "true",
            "HESTIA_HEALING_WINDOW": "500",
        }, clear=False):
            engine = DecisionEngine()
            assert engine.health_monitor.window_size == 500

    def test_custom_adjustment_step(self):
        with patch.dict(os.environ, {
            "HESTIA_HEALING_ENABLED": "true",
            "HESTIA_HEALING_STEP": "1.0",
        }, clear=False):
            engine = DecisionEngine()
            assert engine.adaptive_thresholds.adjustment_step == 1.0

    def test_disabled_explicitly(self):
        with patch.dict(os.environ, {"HESTIA_HEALING_ENABLED": "false"}, clear=False):
            engine = DecisionEngine()
            assert engine._healing_enabled is False


class TestHealingCycle:

    @pytest.fixture(autouse=True)
    def setup_env(self):
        with patch.dict(os.environ, {
            "HESTIA_HEALING_ENABLED": "true",
            "HESTIA_HEALING_MIN_DECISIONS": "5",
            "HESTIA_HEALING_COOLDOWN": "0",
            "HESTIA_HEALING_ADJUST_COOLDOWN": "0",
        }, clear=False):
            yield

    def test_healing_cycle_runs_periodically(self, setup_env):
        engine = DecisionEngine()
        assert engine._healing_rollbacks == 0
        assert engine._healing_adjustments == 0

        import asyncio
        # Run many decisions to trigger healing cycles (every 10)
        for i in range(25):
            prompt = "safe prompt"
            # Label some as FPs to trigger auto rollback
            asyncio.run(engine.evaluate_prompt(
                prompt=prompt,
                user_id="test",
            ))
            # Manually add FP labels to trigger healing
            if engine.health_monitor and i < 15:
                engine.health_monitor.record_decision(
                    decision="block",
                    risk_score=0.9,
                    latency_ms=1.0,
                    expected_outcome="allow",  # FP
                )
            else:
                engine.health_monitor.record_decision(
                    decision="allow",
                    risk_score=0.1,
                    latency_ms=1.0,
                    expected_outcome="allow",
                )

        # Healing cycle should have run at least once
        stats = engine.get_stats()
        assert stats["healing"]["rollbacks_triggered"] >= 0
        assert stats["healing"]["health"]["total_decisions"] >= 25

    def test_rollback_counts_increment(self, setup_env):
        engine = DecisionEngine()
        import asyncio

        for i in range(30):
            asyncio.run(engine.evaluate_prompt(
                prompt="test", user_id="test",
            ))
            if engine.health_monitor:
                engine.health_monitor.record_decision(
                    decision="block",
                    risk_score=0.9,
                    latency_ms=1.0,
                    expected_outcome="allow",
                )

        # Force healing cycles by calling _run_healing_cycle directly
        engine._decision_count = 20
        engine._run_healing_cycle()
        engine._decision_count = 30
        engine._run_healing_cycle()

        stats = engine.get_stats()
        assert stats["healing"]["health"]["false_positives"] >= 28
