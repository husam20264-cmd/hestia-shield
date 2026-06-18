"""
UpdateProtocol for Hestia Shield Federated Learning.

Defines the contribution cycle: encode → privatize → submit → aggregate → retrieve.
Orchestrates the full federated learning pipeline.
"""

import logging
import time
from typing import Any, Dict, List, Optional

from .encoder import LocalEncoder
from .privacy import PrivacyEngine
from .aggregator import FederatedAggregator, Contribution
from .global_intel import GlobalIntel

logger = logging.getLogger(__name__)


class UpdateProtocol:
    """
    Orchestrates the federated learning cycle for a tenant.

    Manages the complete flow:
    1. Encode threat patterns into privacy-preserving embeddings
    2. Add differential privacy noise
    3. Submit to aggregator
    4. Retrieve global patterns
    5. Integrate into local detection

    Usage:
        protocol = UpdateProtocol(tenant_id="ten_123")
        protocol.contribute(prompt="rm -rf /", risk_score=0.95, decision="block")
        global_patterns = protocol.sync()
    """

    def __init__(
        self,
        tenant_id: str,
        encoder: Optional[LocalEncoder] = None,
        privacy: Optional[PrivacyEngine] = None,
        aggregator: Optional[FederatedAggregator] = None,
        global_intel: Optional[GlobalIntel] = None,
        contribution_interval: float = 3600.0,
        sync_interval: float = 3600.0,
        enabled: bool = True,
    ):
        self.tenant_id = tenant_id
        self.encoder = encoder or LocalEncoder()
        self.privacy = privacy or PrivacyEngine(epsilon=1.0)
        self.aggregator = aggregator or FederatedAggregator()
        self.global_intel = global_intel or GlobalIntel()
        self.contribution_interval = contribution_interval
        self.sync_interval = sync_interval
        self.enabled = enabled

        self._last_contribution_time: float = 0.0
        self._last_sync_time: float = 0.0
        self._contribution_count = 0
        self._sync_count = 0

    def contribute(
        self,
        prompt: str = "",
        tool_call: Optional[Dict[str, Any]] = None,
        decision: str = "allow",
        risk_score: float = 0.0,
        environment: str = "development",
        tool_category: str = "",
        previous_blocks: int = 0,
        force: bool = False,
    ) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None

        now = time.time()
        if not force and now - self._last_contribution_time < self.contribution_interval:
            return None

        embedding = self.encoder.encode(
            prompt=prompt,
            tool_call=tool_call,
            decision=decision,
            risk_score=risk_score,
            environment=environment,
            previous_blocks=previous_blocks,
        )

        private_embedding = self.privacy.add_noise(embedding)

        contribution = Contribution(
            tenant_id=self.tenant_id,
            embedding=private_embedding,
            tool_category=tool_category or (tool_call or {}).get("category", ""),
            risk_score=risk_score,
        )

        self.aggregator.submit(contribution)
        self._last_contribution_time = now
        self._contribution_count += 1

        logger.debug(
            "Tenant %s contributed threat pattern (risk=%.2f)",
            self.tenant_id, risk_score,
        )

        return {
            "tenant_id": self.tenant_id,
            "risk_score": risk_score,
            "contribution_count": self._contribution_count,
            "epsilon": self.privacy.epsilon,
        }

    def sync(self, force: bool = False) -> List[Dict[str, Any]]:
        if not self.enabled:
            return []

        now = time.time()
        if not force and now - self._last_sync_time < self.sync_interval:
            return []

        global_embedding = self.aggregator.aggregate()

        results = []
        if global_embedding:
            pattern_id = self.global_intel.ingest(
                embedding=global_embedding,
                tool_category="aggregated",
                avg_risk_score=0.0,
                severity="medium",
            )
            results.append({
                "pattern_id": pattern_id,
                "action": "ingested_global",
            })

            similar = self.global_intel.query_similar(
                global_embedding, top_k=5
            )
            for match in similar:
                results.append({
                    "pattern_id": match["pattern_id"],
                    "similarity": match["similarity"],
                    "action": "similar_found",
                })

        self._last_sync_time = now
        self._sync_count += 1

        return results

    def get_recent_global_patterns(self, limit: int = 20) -> List[Dict]:
        patterns = self.global_intel.get_recent_patterns(limit=limit)
        return [p.to_dict() for p in patterns]

    def get_stats(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "enabled": self.enabled,
            "contribution_count": self._contribution_count,
            "sync_count": self._sync_count,
            "epsilon": self.privacy.epsilon,
            "contribution_interval_seconds": self.contribution_interval,
            "sync_interval_seconds": self.sync_interval,
            "aggregator": self.aggregator.get_stats(),
            "global_intel": self.global_intel.get_stats(),
        }
