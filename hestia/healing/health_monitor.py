"""
HealthMonitor for Hestia Shield Self-Healing.

Tracks decision quality metrics over a sliding window and provides
checkpoints for rollback.
"""

import copy
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class HealthCheckpoint:
    timestamp: float
    window_size: int
    total_decisions: int
    blocked_count: int
    allowed_count: int
    false_positives: int
    false_negatives: int
    avg_latency_ms: float
    fp_rate: float
    fn_rate: float
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DecisionRecord:
    decision: str
    risk_score: float
    latency_ms: float
    expected_outcome: Optional[str]
    timestamp: float = field(default_factory=time.time)


class HealthMonitor:
    """
    Tracks decision quality metrics over a sliding window.

    Compute false positive rate, false negative rate, accuracy, and
    latency statistics. Supports checkpoints for AutoRollback.

    Usage:
        monitor = HealthMonitor(window_size=1000)
        monitor.record_decision(
            decision="block",
            risk_score=0.85,
            latency_ms=5.2,
            expected_outcome="block",  # None if unknown
        )
        stats = monitor.get_stats()
    """

    def __init__(
        self,
        window_size: int = 1000,
        fp_labeler: Optional[Callable[[Dict[str, Any]], bool]] = None,
        fn_labeler: Optional[Callable[[Dict[str, Any]], bool]] = None,
    ):
        self.window_size = window_size
        self._window: Deque[DecisionRecord] = deque(maxlen=window_size)
        self._checkpoints: Deque[HealthCheckpoint] = deque(maxlen=10)
        self._total_decisions = 0
        self._fp_labeler = fp_labeler
        self._fn_labeler = fn_labeler
        self._last_checkpoint_time: float = 0.0

    def record_decision(
        self,
        decision: str,
        risk_score: float,
        latency_ms: float,
        expected_outcome: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        record = DecisionRecord(
            decision=decision,
            risk_score=risk_score,
            latency_ms=latency_ms,
            expected_outcome=expected_outcome,
        )
        self._window.append(record)
        self._total_decisions += 1

    def _compute_outcomes(self) -> Dict[str, int]:
        blocked = sum(1 for r in self._window if r.decision == "block")
        allowed = sum(1 for r in self._window if r.decision == "allow")
        human_review = sum(
            1 for r in self._window if r.decision == "human_review"
        )
        return {
            "blocked": blocked,
            "allowed": allowed,
            "human_review": human_review,
            "total": len(self._window),
        }

    def _compute_false_positives(self) -> int:
        count = 0
        for r in self._window:
            if r.expected_outcome is None:
                continue
            if self._fp_labeler:
                d = {
                    "decision": r.decision,
                    "risk_score": r.risk_score,
                    "expected_outcome": r.expected_outcome,
                }
                if self._fp_labeler(d):
                    count += 1
            else:
                if r.decision == "block" and r.expected_outcome == "allow":
                    count += 1
        return count

    def _compute_false_negatives(self) -> int:
        count = 0
        for r in self._window:
            if r.expected_outcome is None:
                continue
            if self._fn_labeler:
                d = {
                    "decision": r.decision,
                    "risk_score": r.risk_score,
                    "expected_outcome": r.expected_outcome,
                }
                if self._fn_labeler(d):
                    count += 1
            else:
                if r.decision == "allow" and r.expected_outcome == "block":
                    count += 1
        return count

    def _compute_avg_latency(self) -> float:
        if not self._window:
            return 0.0
        total = sum(r.latency_ms for r in self._window)
        return round(total / len(self._window), 2)

    def save_checkpoint(self, context: Optional[Dict[str, Any]] = None) -> HealthCheckpoint:
        stats = self._compute_stats()
        checkpoint = HealthCheckpoint(
            timestamp=time.time(),
            window_size=self.window_size,
            total_decisions=stats["total_decisions"],
            blocked_count=stats["outcomes"]["blocked"],
            allowed_count=stats["outcomes"]["allowed"],
            false_positives=stats["false_positives"],
            false_negatives=stats["false_negatives"],
            avg_latency_ms=stats["avg_latency_ms"],
            fp_rate=stats["fp_rate"],
            fn_rate=stats["fn_rate"],
            context=context or {},
        )
        self._checkpoints.append(checkpoint)
        self._last_checkpoint_time = time.time()
        return checkpoint

    def get_last_checkpoint(self) -> Optional[HealthCheckpoint]:
        if self._checkpoints:
            return self._checkpoints[-1]
        return None

    def get_checkpoints(self) -> List[HealthCheckpoint]:
        return list(self._checkpoints)

    def _compute_stats(self) -> Dict[str, Any]:
        outcomes = self._compute_outcomes()
        fp = self._compute_false_positives()
        fn = self._compute_false_negatives()

        total_labeled = sum(
            1 for r in self._window if r.expected_outcome is not None
        )

        fp_rate = round(fp / total_labeled, 4) if total_labeled > 0 else 0.0
        fn_rate = round(fn / total_labeled, 4) if total_labeled > 0 else 0.0

        correct = total_labeled - fp - fn
        accuracy = round(correct / total_labeled, 4) if total_labeled > 0 else 0.0

        return {
            "window_size": len(self._window),
            "max_window_size": self.window_size,
            "total_decisions": self._total_decisions,
            "outcomes": outcomes,
            "false_positives": fp,
            "false_negatives": fn,
            "total_labeled": total_labeled,
            "fp_rate": fp_rate,
            "fn_rate": fn_rate,
            "accuracy": accuracy,
            "avg_latency_ms": self._compute_avg_latency(),
        }

    def get_stats(self) -> Dict[str, Any]:
        stats = self._compute_stats()
        stats["checkpoints"] = len(self._checkpoints)
        return stats

    def clear(self) -> None:
        self._window.clear()

    def reset(self) -> None:
        self._window.clear()
        self._checkpoints.clear()
        self._total_decisions = 0
