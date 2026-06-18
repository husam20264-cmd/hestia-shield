"""
Hestia Shield v2.1.0 — Federated Learning

Privacy-preserving shared threat intelligence across tenants.
Tenants contribute encrypted embeddings (no raw data) and receive
aggregated global threat patterns.

Usage:
    from hestia.federated import (
        LocalEncoder, PrivacyEngine, FederatedAggregator,
        GlobalIntel, Contribution,
    )
"""

from .encoder import LocalEncoder
from .privacy import PrivacyEngine
from .aggregator import FederatedAggregator, Contribution
from .global_intel import GlobalIntel, GlobalPattern
from .protocol import UpdateProtocol

__all__ = [
    "LocalEncoder",
    "PrivacyEngine",
    "FederatedAggregator",
    "Contribution",
    "GlobalIntel",
    "GlobalPattern",
    "UpdateProtocol",
]
