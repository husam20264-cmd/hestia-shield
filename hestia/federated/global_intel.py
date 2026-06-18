"""
GlobalIntel for Hestia Shield Federated Learning.

Stores and retrieves aggregated global threat patterns.
Provides query interface to find similar patterns to local threats.
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class GlobalPattern:
    pattern_id: str
    embedding: Dict[str, float]
    tool_category: str = ""
    avg_risk_score: float = 0.0
    report_count: int = 1
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    severity: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "tool_category": self.tool_category,
            "avg_risk_score": self.avg_risk_score,
            "report_count": self.report_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "severity": self.severity,
        }


class GlobalIntel:
    """
    Global threat intelligence repository.

    Stores aggregated patterns from the FederatedAggregator and
    provides similarity search to find matching global patterns
    for local threat queries.

    Usage:
        intel = GlobalIntel()
        intel.ingest(global_embedding)
        matches = intel.query_similar(local_embedding, top_k=5)
    """

    def __init__(
        self,
        similarity_fn: Optional[Callable[[Dict, Dict], float]] = None,
        max_patterns: int = 10000,
    ):
        self._patterns: Dict[str, GlobalPattern] = {}
        self._max_patterns = max_patterns
        self._similarity_fn = similarity_fn or self._cosine_similarity
        self._query_count = 0
        self._ingestion_count = 0

    def ingest(
        self,
        embedding: Dict[str, float],
        tool_category: str = "",
        avg_risk_score: float = 0.0,
        severity: str = "medium",
    ) -> str:
        pattern_id = f"gp_{int(time.time() * 1000)}_{self._ingestion_count}"

        pattern = GlobalPattern(
            pattern_id=pattern_id,
            embedding=embedding,
            tool_category=tool_category,
            avg_risk_score=avg_risk_score,
            severity=severity,
        )

        self._patterns[pattern_id] = pattern
        self._ingestion_count += 1

        if len(self._patterns) > self._max_patterns:
            oldest = min(
                self._patterns.keys(),
                key=lambda pid: self._patterns[pid].last_seen,
            )
            del self._patterns[oldest]

        return pattern_id

    def query_similar(
        self,
        embedding: Dict[str, float],
        top_k: int = 5,
        min_score: float = 0.3,
    ) -> List[Dict[str, Any]]:
        scored: List[Tuple[float, GlobalPattern]] = []

        for pattern in self._patterns.values():
            sim = self._similarity_fn(embedding, pattern.embedding)
            if sim >= min_score:
                scored.append((sim, pattern))

        scored.sort(key=lambda x: x[0], reverse=True)
        self._query_count += 1

        results = []
        for sim, pattern in scored[:top_k]:
            result = pattern.to_dict()
            result["similarity"] = round(sim, 4)
            results.append(result)

        return results

    def get_pattern_by_id(self, pattern_id: str) -> Optional[GlobalPattern]:
        return self._patterns.get(pattern_id)

    def get_recent_patterns(self, limit: int = 50) -> List[GlobalPattern]:
        sorted_patterns = sorted(
            self._patterns.values(),
            key=lambda p: p.last_seen,
            reverse=True,
        )
        return sorted_patterns[:limit]

    def get_high_risk_patterns(
        self, min_risk: float = 0.7, limit: int = 20
    ) -> List[GlobalPattern]:
        high_risk = [
            p for p in self._patterns.values()
            if p.avg_risk_score >= min_risk
        ]
        high_risk.sort(key=lambda p: p.avg_risk_score, reverse=True)
        return high_risk[:limit]

    def report_matches(
        self,
        embedding: Dict[str, float],
        top_k: int = 5,
    ) -> int:
        matches = self.query_similar(embedding, top_k=top_k)
        return len(matches)

    def clear(self) -> None:
        self._patterns.clear()

    @staticmethod
    def _cosine_similarity(
        a: Dict[str, float], b: Dict[str, float]
    ) -> float:
        all_keys = set(a.keys()) | set(b.keys())
        dot = 0.0
        norm_a = 0.0
        norm_b = 0.0
        for key in all_keys:
            va = a.get(key, 0.0)
            vb = b.get(key, 0.0)
            dot += va * vb
            norm_a += va * va
            norm_b += vb * vb
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / ((norm_a ** 0.5) * (norm_b ** 0.5))

    def get_stats(self) -> Dict[str, Any]:
        severities = defaultdict(int)
        for p in self._patterns.values():
            severities[p.severity] += 1

        return {
            "total_patterns": len(self._patterns),
            "max_patterns": self._max_patterns,
            "ingestion_count": self._ingestion_count,
            "query_count": self._query_count,
            "severity_distribution": dict(severities),
            "high_risk_patterns": len(self.get_high_risk_patterns()),
        }
