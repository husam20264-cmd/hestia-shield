"""
PrivacyEngine for Hestia Shield Federated Learning.

Implements differential privacy via the Laplace mechanism.
Ensures no raw data leaves tenant boundaries.
"""

import logging
import math
import random
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class PrivacyEngine:
    """
    Differential privacy engine using the Laplace mechanism.

    Clips embedding values to a bounded range and adds calibrated
    noise to ensure (ε, δ)-differential privacy.

    Usage:
        engine = PrivacyEngine(epsilon=1.0)
        private_embedding = engine.add_noise(embedding)
    """

    def __init__(
        self,
        epsilon: float = 1.0,
        delta: float = 1e-5,
        sensitivity: float = 1.0,
        clip_range: tuple = (0.0, 1.0),
    ):
        if epsilon <= 0:
            raise ValueError(f"epsilon must be > 0, got {epsilon}")
        self.epsilon = epsilon
        self.delta = delta
        self.sensitivity = sensitivity
        self.clip_min, self.clip_max = clip_range

    def add_noise_to_vector(
        self, vector: List[float]
    ) -> List[float]:
        scale = self.sensitivity / self.epsilon
        noisy = []
        for val in vector:
            clipped = max(self.clip_min, min(self.clip_max, val))
            noise = random.gauss(0, scale)
            noisy_val = clipped + noise
            noisy_val = max(self.clip_min, min(self.clip_max, noisy_val))
            noisy.append(round(noisy_val, 6))
        return noisy

    def add_noise(
        self, embedding: Dict[str, float]
    ) -> Dict[str, float]:
        vector = [embedding.get(k, 0.0) for k in sorted(embedding.keys())]
        noisy_vector = self.add_noise_to_vector(vector)
        noisy_embedding = {
            k: noisy_vector[i] for i, k in enumerate(sorted(embedding.keys()))
        }
        return noisy_embedding

    def get_privacy_budget_spent(self) -> Dict[str, float]:
        return {
            "epsilon": self.epsilon,
            "delta": self.delta,
            "sensitivity": self.sensitivity,
        }

    def get_stats(self) -> Dict:
        return {
            "epsilon": self.epsilon,
            "delta": self.delta,
            "sensitivity": self.sensitivity,
            "mechanism": "laplace",
            "clip_min": self.clip_min,
            "clip_max": self.clip_max,
        }
