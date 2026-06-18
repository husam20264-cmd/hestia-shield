"""
Tests for Hestia Shield v2.0.0 — Self-Healing Systems
"""

import pytest
import time

from hestia.healing import (
    HealthMonitor,
    HealthCheckpoint,
    AutoRollback,
    AdaptiveThresholds,
)


class TestHealthMonitor:
    """Tests for HealthMonitor."""

    def test_empty_monitor_stats(self):
        monitor = HealthMonitor(window_size=100)
        stats = monitor.get_stats()
        assert stats["window_size"] == 0
        assert stats["fp_rate"] == 0.0
        assert stats["fn_rate"] == 0.0
        assert stats["accuracy"] == 0.0

    def test_record_decision_increments_count(self):
        monitor = HealthMonitor(window_size=100)
        monitor.record_decision("allow", 0.1, 2.0)
        monitor.record_decision("block", 0.9, 5.0)
        stats = monitor.get_stats()
        assert stats["total_decisions"] == 2
        assert stats["window_size"] == 2

    def test_outcomes_counted_correctly(self):
        monitor = HealthMonitor(window_size=100)
        monitor.record_decision("allow", 0.1, 1.0)
        monitor.record_decision("block", 0.9, 2.0)
        monitor.record_decision("block", 0.8, 3.0)
        monitor.record_decision("human_review", 0.6, 4.0)
        stats = monitor.get_stats()
        assert stats["outcomes"]["allowed"] == 1
        assert stats["outcomes"]["blocked"] == 2
        assert stats["outcomes"]["human_review"] == 1

    def test_false_positive_detection(self):
        monitor = HealthMonitor(window_size=100)
        monitor.record_decision("block", 0.9, 2.0, expected_outcome="allow")
        monitor.record_decision("allow", 0.1, 1.0, expected_outcome="allow")
        monitor.record_decision("block", 0.8, 3.0, expected_outcome="block")
        stats = monitor.get_stats()
        assert stats["false_positives"] == 1
        assert stats["false_negatives"] == 0
        assert stats["total_labeled"] == 3

    def test_false_negative_detection(self):
        monitor = HealthMonitor(window_size=100)
        monitor.record_decision("allow", 0.1, 1.0, expected_outcome="block")
        monitor.record_decision("allow", 0.2, 2.0, expected_outcome="block")
        monitor.record_decision("block", 0.9, 3.0, expected_outcome="block")
        stats = monitor.get_stats()
        assert stats["false_positives"] == 0
        assert stats["false_negatives"] == 2
        assert stats["total_labeled"] == 3

    def test_accuracy_computation(self):
        monitor = HealthMonitor(window_size=100)
        monitor.record_decision("allow", 0.1, 1.0, expected_outcome="allow")
        monitor.record_decision("block", 0.9, 2.0, expected_outcome="block")
        monitor.record_decision("block", 0.8, 3.0, expected_outcome="allow")
        stats = monitor.get_stats()
        assert stats["total_labeled"] == 3
        assert stats["false_positives"] == 1
        assert stats["accuracy"] == round(2 / 3, 4)

    def test_average_latency(self):
        monitor = HealthMonitor(window_size=100)
        monitor.record_decision("allow", 0.1, 2.0)
        monitor.record_decision("block", 0.9, 4.0)
        monitor.record_decision("allow", 0.2, 6.0)
        stats = monitor.get_stats()
        assert stats["avg_latency_ms"] == 4.0

    def test_sliding_window_respects_max_size(self):
        monitor = HealthMonitor(window_size=3)
        for _ in range(10):
            monitor.record_decision("allow", 0.1, 1.0)
        stats = monitor.get_stats()
        assert stats["window_size"] == 3

    def test_save_checkpoint(self):
        monitor = HealthMonitor(window_size=100)
        monitor.record_decision("block", 0.9, 2.0, expected_outcome="allow")
        monitor.record_decision("allow", 0.1, 1.0, expected_outcome="allow")
        checkpoint = monitor.save_checkpoint({"note": "test"})
        assert isinstance(checkpoint, HealthCheckpoint)
        assert checkpoint.false_positives == 1
        assert checkpoint.context["note"] == "test"

    def test_get_last_checkpoint(self):
        monitor = HealthMonitor(window_size=100)
        assert monitor.get_last_checkpoint() is None
        c1 = monitor.save_checkpoint()
        c2 = monitor.save_checkpoint()
        assert monitor.get_last_checkpoint() is c2

    def test_get_checkpoints(self):
        monitor = HealthMonitor(window_size=100)
        monitor.save_checkpoint()
        monitor.save_checkpoint()
        assert len(monitor.get_checkpoints()) == 2

    def test_clear(self):
        monitor = HealthMonitor(window_size=100)
        monitor.record_decision("allow", 0.1, 1.0)
        assert monitor.get_stats()["window_size"] == 1
        monitor.clear()
        assert monitor.get_stats()["window_size"] == 0

    def test_reset(self):
        monitor = HealthMonitor(window_size=100)
        monitor.record_decision("allow", 0.1, 1.0)
        monitor.save_checkpoint()
        assert monitor.get_stats()["total_decisions"] == 1
        assert len(monitor.get_checkpoints()) == 1
        monitor.reset()
        assert monitor.get_stats()["total_decisions"] == 0
        assert len(monitor.get_checkpoints()) == 0

    def test_fp_rate_computation(self):
        monitor = HealthMonitor(window_size=100)
        # 2 FPs out of 4 labeled
        monitor.record_decision("block", 0.9, 1.0, expected_outcome="allow")
        monitor.record_decision("block", 0.8, 1.0, expected_outcome="allow")
        monitor.record_decision("allow", 0.1, 1.0, expected_outcome="allow")
        monitor.record_decision("block", 0.9, 1.0, expected_outcome="block")
        stats = monitor.get_stats()
        assert stats["false_positives"] == 2
        assert stats["fp_rate"] == 0.5

    def test_custom_fp_labeler(self):
        def custom_fp(d):
            return d["decision"] == "block" and d["risk_score"] > 0.95
        monitor = HealthMonitor(window_size=100, fp_labeler=custom_fp)
        monitor.record_decision("block", 0.99, 1.0, expected_outcome="allow")
        monitor.record_decision("block", 0.80, 1.0, expected_outcome="allow")
        stats = monitor.get_stats()
        assert stats["false_positives"] == 1


class TestAutoRollback:
    """Tests for AutoRollback."""

    def test_tick_noop_when_fp_below_threshold(self):
        monitor = HealthMonitor(window_size=100)
        # All correct decisions -> no FPs
        for _ in range(60):
            monitor.record_decision("allow", 0.1, 1.0, expected_outcome="allow")

        rollback_called = False
        def rollback_fn():
            nonlocal rollback_called
            rollback_called = True
            return True

        ar = AutoRollback(monitor, rollback_fn, min_decisions_before_rollback=50)
        result = ar.tick()
        assert result is None
        assert not rollback_called

    def test_tick_triggers_rollback_on_high_fp(self):
        monitor = HealthMonitor(window_size=100)
        # High FP rate: 30 FPs out of 60 labeled
        for i in range(60):
            expected = "allow" if i < 30 else "block"
            monitor.record_decision(
                "block", 0.9, 1.0,
                expected_outcome=expected,
            )

        rollback_called = False
        def rollback_fn():
            nonlocal rollback_called
            rollback_called = True
            return True

        ar = AutoRollback(
            monitor, rollback_fn,
            fp_threshold=0.05,
            min_decisions_before_rollback=50,
            cooldown_seconds=0,
        )
        result = ar.tick()
        assert result is not None
        assert result["rolled_back"] is True
        assert rollback_called

    def test_tick_not_enough_decisions(self):
        monitor = HealthMonitor(window_size=100)
        monitor.record_decision("block", 0.9, 1.0, expected_outcome="allow")

        ar = AutoRollback(monitor, lambda: True, min_decisions_before_rollback=50)
        result = ar.tick()
        assert result is None

    def test_cooldown_respects_time(self):
        monitor = HealthMonitor(window_size=100)
        for i in range(60):
            expected = "allow" if i < 30 else "block"
            monitor.record_decision(
                "block", 0.9, 1.0, expected_outcome=expected,
            )

        call_count = 0
        def rollback_fn():
            nonlocal call_count
            call_count += 1
            return True

        ar = AutoRollback(
            monitor, rollback_fn,
            fp_threshold=0.05,
            min_decisions_before_rollback=50,
            cooldown_seconds=3600,
        )
        result1 = ar.tick()
        assert result1 is not None
        assert result1["rolled_back"] is True

        result2 = ar.tick()
        assert result2 is None

        assert call_count == 1

    def test_rollback_fn_failure_handled(self):
        monitor = HealthMonitor(window_size=100)
        for i in range(60):
            expected = "allow" if i < 30 else "block"
            monitor.record_decision(
                "block", 0.9, 1.0, expected_outcome=expected,
            )

        def failing_fn():
            raise RuntimeError("Rollback failed")

        ar = AutoRollback(
            monitor, failing_fn,
            fp_threshold=0.05,
            min_decisions_before_rollback=50,
            cooldown_seconds=0,
        )
        result = ar.tick()
        assert result is not None
        assert result["rolled_back"] is False
        assert "error" in result

    def test_suppressed_does_not_rollback(self):
        monitor = HealthMonitor(window_size=100)
        for i in range(60):
            expected = "allow" if i < 30 else "block"
            monitor.record_decision(
                "block", 0.9, 1.0, expected_outcome=expected,
            )

        ar = AutoRollback(
            monitor, lambda: True,
            fp_threshold=0.05,
            min_decisions_before_rollback=50,
            cooldown_seconds=0,
        )
        ar.suppressed = True
        result = ar.tick()
        assert result is None

    def test_stats(self):
        monitor = HealthMonitor()
        ar = AutoRollback(monitor, lambda: True)
        stats = ar.get_stats()
        assert stats["rollbacks_triggered"] == 0
        assert stats["fp_threshold"] == 0.05
        assert "suppressed" in stats


class TestAdaptiveThresholds:
    """Tests for AdaptiveThresholds."""

    def test_tick_noop_when_within_targets(self):
        monitor = HealthMonitor(window_size=100)
        for _ in range(60):
            monitor.record_decision(
                "allow", 0.1, 1.0, expected_outcome="allow",
            )

        thresholds = {"critical": 0.85, "high": 0.65}
        adjusted = {}
        def set_fn(t):
            adjusted.update(t)

        adapter = AdaptiveThresholds(
            monitor, thresholds, set_fn,
            min_decisions=50,
            cooldown_seconds=0,
        )
        result = adapter.tick()
        assert result is None

    def test_lowers_thresholds_on_high_fp(self):
        monitor = HealthMonitor(window_size=100)
        # High FP rate: 30 FPs out of 60 labeled
        for i in range(60):
            expected = "allow" if i < 30 else "block"
            monitor.record_decision(
                "block", 0.9, 1.0, expected_outcome=expected,
            )

        thresholds = {"critical": 0.85, "high": 0.65}
        adjusted = {}
        def set_fn(t):
            adjusted.update(t)

        adapter = AdaptiveThresholds(
            monitor, thresholds, set_fn,
            fp_target=0.05,
            min_decisions=50,
            cooldown_seconds=0,
        )
        result = adapter.tick()
        assert result is not None
        assert result["adjusted"] is True
        # Thresholds should be lowered
        for key in thresholds:
            assert adjusted[key] < thresholds[key]

    def test_raises_thresholds_on_high_fn(self):
        monitor = HealthMonitor(window_size=100)
        # High FN rate: 30 FNs out of 60 labeled
        for i in range(60):
            expected = "block" if i < 30 else "allow"
            monitor.record_decision(
                "allow", 0.1, 1.0, expected_outcome=expected,
            )

        thresholds = {"critical": 0.85, "high": 0.65}
        adjusted = {}
        def set_fn(t):
            adjusted.update(t)

        adapter = AdaptiveThresholds(
            monitor, thresholds, set_fn,
            fn_target=0.02,
            min_decisions=50,
            cooldown_seconds=0,
        )
        result = adapter.tick()
        assert result is not None
        assert result["adjusted"] is True
        for key in thresholds:
            assert adjusted[key] > thresholds[key]

    def test_not_enough_decisions(self):
        monitor = HealthMonitor(window_size=100)
        monitor.record_decision("allow", 0.1, 1.0, expected_outcome="allow")

        adapter = AdaptiveThresholds(
            monitor, {"critical": 0.85}, lambda t: None,
            min_decisions=50,
        )
        result = adapter.tick()
        assert result is None

    def test_thresholds_clamped_to_min(self):
        monitor = HealthMonitor(window_size=100)
        for i in range(60):
            expected = "allow" if i < 30 else "block"
            monitor.record_decision(
                "block", 0.9, 1.0, expected_outcome=expected,
            )

        thresholds = {"critical": 0.12}
        adjusted = {}
        def set_fn(t):
            adjusted.update(t)

        adapter = AdaptiveThresholds(
            monitor, thresholds, set_fn,
            fp_target=0.05,
            min_threshold=0.10,
            adjustment_step=0.1,
            min_decisions=50,
            cooldown_seconds=0,
        )
        adapter.tick()
        assert adjusted["critical"] >= 0.10

    def test_thresholds_clamped_to_max(self):
        monitor = HealthMonitor(window_size=100)
        for i in range(60):
            expected = "block" if i < 30 else "allow"
            monitor.record_decision(
                "allow", 0.1, 1.0, expected_outcome=expected,
            )

        thresholds = {"critical": 0.90}
        adjusted = {}
        def set_fn(t):
            adjusted.update(t)

        adapter = AdaptiveThresholds(
            monitor, thresholds, set_fn,
            fn_target=0.02,
            max_threshold=0.95,
            adjustment_step=0.1,
            min_decisions=50,
            cooldown_seconds=0,
        )
        adapter.tick()
        assert adjusted["critical"] <= 0.95

    def test_cooldown_respected(self):
        monitor = HealthMonitor(window_size=100)
        for _ in range(60):
            monitor.record_decision(
                "block", 0.9, 1.0, expected_outcome="allow",
            )

        thresholds = {"critical": 0.85}
        call_count = 0
        def set_fn(t):
            nonlocal call_count
            call_count += 1

        adapter = AdaptiveThresholds(
            monitor, thresholds, set_fn,
            fp_target=0.05,
            min_decisions=50,
            cooldown_seconds=3600,
        )
        r1 = adapter.tick()
        assert r1 is not None
        r2 = adapter.tick()
        assert r2 is None
        assert call_count == 1

    def test_set_fn_failure_handled(self):
        monitor = HealthMonitor(window_size=100)
        for i in range(60):
            expected = "allow" if i < 30 else "block"
            monitor.record_decision(
                "block", 0.9, 1.0, expected_outcome=expected,
            )

        def failing_fn(t):
            raise RuntimeError("Set failed")

        adapter = AdaptiveThresholds(
            monitor, {"critical": 0.85}, failing_fn,
            fp_target=0.05,
            min_decisions=50,
            cooldown_seconds=0,
        )
        result = adapter.tick()
        assert result is not None
        assert result["adjusted"] is True
        assert "error" in result

    def test_thresholds_property(self):
        monitor = HealthMonitor()
        adapter = AdaptiveThresholds(
            monitor, {"critical": 0.85, "high": 0.65}, lambda t: None,
        )
        t = adapter.thresholds
        assert t["critical"] == 0.85
        assert t["high"] == 0.65

    def test_stats(self):
        monitor = HealthMonitor()
        adapter = AdaptiveThresholds(
            monitor, {"critical": 0.85}, lambda t: None,
        )
        stats = adapter.get_stats()
        assert stats["adjustments_made"] == 0
        assert stats["current_thresholds"]["critical"] == 0.85
        assert stats["fp_target"] == 0.05

    def test_adjustment_history(self):
        monitor = HealthMonitor(window_size=100)
        for i in range(60):
            expected = "allow" if i < 30 else "block"
            monitor.record_decision(
                "block", 0.9, 1.0, expected_outcome=expected,
            )

        adapter = AdaptiveThresholds(
            monitor, {"critical": 0.85}, lambda t: None,
            fp_target=0.05,
            min_decisions=50,
            cooldown_seconds=0,
        )
        adapter.tick()
        assert len(adapter._history) == 1
        assert adapter._history[0]["adjusted"] is True
        assert "thresholds_before" in adapter._history[0]
        assert "thresholds_after" in adapter._history[0]
