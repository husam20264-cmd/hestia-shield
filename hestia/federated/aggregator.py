"""
FederatedAggregator for Hestia Shield.

Collects privacy-preserving embeddings from multiple tenants
and performs secure aggregation to produce global threat patterns.
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class Contribution:
    tenant_id: str
    embedding: Dict[str, float]
    tool_category: str = ""
    risk_score: float = 0.0
    timestamp: float = field(default_factory=time.time)
    weight: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "tool_category": self.tool_category,
            "risk_score": self.risk_score,
            "timestamp": self.timestamp,
            "weight": self.weight,
        }


class FederatedAggregator:
    """
    Aggregates privacy-preserving embeddings from multiple tenants.

    Uses federated averaging (FedAvg): each tenant's contribution is
    weighted equally, then averaged to produce a global embedding.

    Usage:
        aggregator = FederatedAggregator()
        aggregator.submit(Contribution(tenant_id="ten_1", embedding={...}))
        global_emb = aggregator.aggregate()
    """

    def __init__(
        self,
        min_contributions: int = 1,
        aggregation_window: float = 86400.0,
    ):
        self.min_contributions = min_contributions
        self.aggregation_window = aggregation_window
        self._contributions: List[Contribution] = []
        self._aggregation_count = 0
        self._last_aggregation_time: float = 0.0
        self._global_embedding: Optional[Dict[str, float]] = None

    def submit(self, contribution: Contribution) -> None:
        self._contributions.append(contribution)

    def _get_recent_contributions(self) -> List[Contribution]:
        now = time.time()
        cutoff = now - self.aggregation_window
        return [c for c in self._contributions if c.timestamp >= cutoff]

    def aggregate(self) -> Optional[Dict[str, float]]:
        recent = self._get_recent_contributions()
        if len(recent) < self.min_contributions:
            logger.debug(
                "Not enough contributions: %d < %d",
                len(recent), self.min_contributions,
            )
            return None

        if not recent:
            return None

        all_keys = sorted(recent[0].embedding.keys())
        total_weight = sum(c.weight for c in recent)

        global_vector = []
        for key in all_keys:
            weighted_sum = sum(
                c.embedding.get(key, 0.0) * c.weight for c in recent
            )
            avg = weighted_sum / total_weight if total_weight > 0 else 0.0
            global_vector.append(round(avg, 6))

        self._global_embedding = {
            key: global_vector[i] for i, key in enumerate(all_keys)
        }
        self._aggregation_count += 1
        self._last_aggregation_time = time.time()

        logger.info(
            "Aggregated %d contributions from %d unique tenants",
            len(recent),
            len(set(c.tenant_id for c in recent)),
        )

        return dict(self._global_embedding)

    def get_contributions(
        self,
        tenant_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Contribution]:
        filtered = self._contributions
        if tenant_id:
            filtered = [c for c in filtered if c.tenant_id == tenant_id]
        return filtered[-limit:]

    def get_contribution_count(self, tenant_id: Optional[str] = None) -> int:
        if tenant_id:
            return sum(1 for c in self._contributions if c.tenant_id == tenant_id)
        return len(self._contributions)

    def reset(self) -> None:
        self._contributions.clear()
        self._global_embedding = None

    def get_stats(self) -> Dict[str, Any]:
        recent = self._get_recent_contributions()
        unique_tenants = len(set(c.tenant_id for c in recent))

        tool_categories = defaultdict(int)
        for c in recent:
            if c.tool_category:
                tool_categories[c.tool_category] += 1

        return {
            "total_contributions": len(self._contributions),
            "recent_contributions": len(recent),
            "unique_tenants": unique_tenants,
            "aggregations_performed": self._aggregation_count,
            "min_contributions_required": self.min_contributions,
            "aggregation_window_hours": round(
                self.aggregation_window / 3600, 1
            ),
            "tool_categories": dict(tool_categories),
            "has_global_embedding": self._global_embedding is not None,
        }
