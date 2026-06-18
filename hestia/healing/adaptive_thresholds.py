"""
AdaptiveThresholds for Hestia Shield Self-Healing.

Dynamically adjusts risk thresholds based on observed false positive
and false negative rates from the HealthMonitor.
"""

import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

from .health_monitor import HealthMonitor

logger = logging.getLogger(__name__)


class AdaptiveThresholds:
    """
    Dynamically adjust risk thresholds to balance FP and FN rates.

    Watches a HealthMonitor and adjusts thresholds via a setter function.
    Lowers thresholds when FP is high (less sensitive). Raises thresholds
    when FN is high (more sensitive).

    Usage:
        adapter = AdaptiveThresholds(
            monitor=health_monitor,
            thresholds={"critical": 0.85, "high": 0.65, "medium": 0.40},
            set_thresholds_fn=lambda t: classifier.update_thresholds(t),
        )
        adapter.tick()  # call periodically
    """

    def __init__(
        self,
        monitor: HealthMonitor,
        thresholds: Dict[str, float],
        set_thresholds_fn: Callable[[Dict[str, float]], None],
        fp_target: float = 0.05,
        fn_target: float = 0.02,
        adjustment_step: float = 0.02,
        min_threshold: float = 0.10,
        max_threshold: float = 0.95,
        min_decisions: int = 50,
        cooldown_seconds: float = 120.0,
    ):
        self.monitor = monitor
        self._thresholds = dict(thresholds)
        self.set_thresholds_fn = set_thresholds_fn
        self.fp_target = fp_target
        self.fn_target = fn_target
        self.adjustment_step = adjustment_step
        self.min_threshold = min_threshold
        self.max_threshold = max_threshold
        self.min_decisions = min_decisions
        self.cooldown_seconds = cooldown_seconds

        self._adjustments_made = 0
        self._last_adjustment_time: float = 0.0
        self._history: List[Dict[str, Any]] = []

    @property
    def thresholds(self) -> Dict[str, float]:
        return dict(self._thresholds)

    def tick(self) -> Optional[Dict[str, Any]]:
        """
        Evaluate health metrics and adjust thresholds if needed.

        Returns a dict describing the adjustment, or None.
        """
        import time
        now = time.time()
        if now - self._last_adjustment_time < self.cooldown_seconds:
            return None

        stats = self.monitor.get_stats()
        labeled = stats["total_labeled"]

        if labeled < self.min_decisions:
            return None

        fp_rate = stats["fp_rate"]
        fn_rate = stats["fn_rate"]

        adjustment: Dict[str, Any] = {
            "fp_rate": fp_rate,
            "fn_rate": fn_rate,
            "fp_target": self.fp_target,
            "fn_target": self.fn_target,
            "thresholds_before": dict(self._thresholds),
            "adjusted": False,
        }

        adjustment_made = False

        # If FP is too high, lower thresholds (less sensitive)
        if fp_rate > self.fp_target * 1.5:
            self._adjust_thresholds(-self.adjustment_step)
            adjustment_made = True
            adjustment["reason_fp"] = (
                f"FP rate {fp_rate:.2%} > target {self.fp_target:.2%}, "
                f"lowering thresholds"
            )

        # If FN is too high, raise thresholds (more sensitive)
        if fn_rate > self.fn_target * 1.5:
            self._adjust_thresholds(self.adjustment_step)
            adjustment_made = True
            adjustment["reason_fn"] = (
                f"FN rate {fn_rate:.2%} > target {self.fn_target:.2%}, "
                f"raising thresholds"
            )

        if adjustment_made:
            self._adjustments_made += 1
            self._last_adjustment_time = now
            adjustment["adjusted"] = True
            adjustment["thresholds_after"] = dict(self._thresholds)

            try:
                self.set_thresholds_fn(self._thresholds)
            except Exception as e:
                adjustment["error"] = str(e)
                logger.error("AdaptiveThresholds set failed: %s", e)

            self._history.append(adjustment)
            logger.info(
                "AdaptiveThresholds: adjusted thresholds to %s",
                self._thresholds,
            )

        return adjustment if adjustment_made else None

    def _adjust_thresholds(self, delta: float) -> None:
        for key in self._thresholds:
            new_val = self._thresholds[key] + delta
            new_val = max(self.min_threshold, min(self.max_threshold, new_val))
            self._thresholds[key] = round(new_val, 2)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "adjustments_made": self._adjustments_made,
            "current_thresholds": dict(self._thresholds),
            "fp_target": self.fp_target,
            "fn_target": self.fn_target,
            "adjustment_step": self.adjustment_step,
            "cooldown_seconds": self.cooldown_seconds,
            "min_decisions": self.min_decisions,
        }
