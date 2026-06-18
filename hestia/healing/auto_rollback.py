"""
AutoRollback for Hestia Shield Self-Healing.

Monitors HealthMonitor metrics and triggers automatic policy rollback
when false positive rate exceeds the configured threshold.
"""

import logging
from typing import Any, Callable, Dict, Optional

from .health_monitor import HealthMonitor

logger = logging.getLogger(__name__)


class AutoRollback:
    """
    Automatic policy rollback when system health degrades.

    Watches a HealthMonitor and triggers a rollback when the false
    positive rate exceeds a configurable threshold.

    Usage:
        rollback = AutoRollback(
            monitor=health_monitor,
            rollback_fn=lambda: policy_applier.rollback(),
            fp_threshold=0.05,
            checkpoint_interval=100,
        )
        rollback.tick()  # call periodically
    """

    def __init__(
        self,
        monitor: HealthMonitor,
        rollback_fn: Callable[[], bool],
        fp_threshold: float = 0.05,
        checkpoint_interval: int = 100,
        min_decisions_before_rollback: int = 50,
        cooldown_seconds: float = 300.0,
    ):
        self.monitor = monitor
        self.rollback_fn = rollback_fn
        self.fp_threshold = fp_threshold
        self.checkpoint_interval = checkpoint_interval
        self.min_decisions = min_decisions_before_rollback
        self.cooldown_seconds = cooldown_seconds

        self._rollbacks_triggered = 0
        self._last_rollback_time: float = 0.0
        self._last_decision_count = 0
        self._suppressed = False

    @property
    def suppressed(self) -> bool:
        return self._suppressed

    @suppressed.setter
    def suppressed(self, value: bool) -> None:
        self._suppressed = value

    def tick(self) -> Optional[Dict[str, Any]]:
        """
        Evaluate health and trigger rollback if needed.

        Returns a dict describing the action taken, or None.
        """
        if self._suppressed:
            return None

        stats = self.monitor.get_stats()
        total = stats["total_decisions"]
        labeled = stats["total_labeled"]

        if labeled < self.min_decisions:
            return None

        fp_rate = stats["fp_rate"]
        fp_count = stats["false_positives"]

        import time
        now = time.time()
        if now - self._last_rollback_time < self.cooldown_seconds:
            return None

        if fp_rate <= self.fp_threshold:
            return None

        result: Dict[str, Any] = {
            "fp_rate": fp_rate,
            "fp_threshold": self.fp_threshold,
            "labeled_decisions": labeled,
            "false_positives": fp_count,
            "rolled_back": False,
        }

        try:
            success = self.rollback_fn()
            if success:
                self._rollbacks_triggered += 1
                self._last_rollback_time = now
                result["rolled_back"] = True
                result["reason"] = (
                    f"FP rate {fp_rate:.2%} exceeded threshold "
                    f"{self.fp_threshold:.2%}"
                )
                logger.warning(
                    "AutoRollback: %s", result["reason"]
                )
        except Exception as e:
            result["error"] = str(e)
            logger.error("AutoRollback failed: %s", e)

        self._last_decision_count = total
        return result

    def get_stats(self) -> Dict[str, Any]:
        return {
            "rollbacks_triggered": self._rollbacks_triggered,
            "fp_threshold": self.fp_threshold,
            "checkpoint_interval": self.checkpoint_interval,
            "min_decisions": self.min_decisions,
            "cooldown_seconds": self.cooldown_seconds,
            "suppressed": self._suppressed,
        }
