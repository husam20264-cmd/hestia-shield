"""
LocalEncoder for Hestia Shield Federated Learning.

Converts threat patterns (prompts, tool calls) into fixed-size
feature embeddings that can be shared without exposing raw data.
"""

import logging
import math
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Default feature dimensions for the embedding vector
# Matches the existing FeatureExtractor output shape
EMBEDDING_FEATURES: List[str] = [
    "prompt_length",
    "word_count",
    "digit_ratio",
    "uppercase_ratio",
    "special_char_ratio",
    "has_dangerous_keyword",
    "high_risk_score",
    "tool_critical",
    "tool_write_category",
    "is_production_env",
    "has_arguments",
    "was_blocked",
    "risk_level_critical",
    "risk_level_high",
    "risk_level_medium",
    "num_previous_blocks",
]

EMBEDDING_DIM = len(EMBEDDING_FEATURES)

# Dangerous keywords for prompt analysis
DANGEROUS_KEYWORDS: Set[str] = {
    "rm -rf", "delete all", "drop table", "format disk",
    "destroy", "wipe", "purge", "bypass security",
    "disable firewall", "escalate privileges", "exploit",
    "injection", "credential theft", "backdoor",
}

# Critical tool categories
CRITICAL_TOOL_CATEGORIES: Set[str] = {
    "execute", "finance", "admin", "shell", "database",
}

# Write tool categories
WRITE_TOOL_CATEGORIES: Set[str] = {
    "write", "create", "delete", "modify", "upload",
}


class LocalEncoder:
    """
    Converts threat patterns into privacy-preserving embeddings.

    The embedding is a fixed-size vector of floats that captures
    threat-relevant features without containing raw text or
    personally identifiable information.

    Usage:
        encoder = LocalEncoder()
        embedding = encoder.encode(prompt="rm -rf /", tool_call={})
    """

    def __init__(self, embedding_dim: int = EMBEDDING_DIM):
        self.embedding_dim = embedding_dim

    def encode(
        self,
        prompt: str = "",
        tool_call: Optional[Dict[str, Any]] = None,
        decision: str = "allow",
        risk_score: float = 0.0,
        environment: str = "development",
        previous_blocks: int = 0,
    ) -> Dict[str, float]:
        tool_call = tool_call or {}

        prompt_lower = prompt.lower()
        words = prompt_lower.split() if prompt else []
        num_words = len(words)
        num_chars = len(prompt)

        digit_count = sum(1 for c in prompt if c.isdigit())
        uppercase_count = sum(1 for c in prompt if c.isupper())
        special_count = sum(
            1 for c in prompt if not c.isalnum() and not c.isspace()
        )

        has_dangerous = any(kw in prompt_lower for kw in DANGEROUS_KEYWORDS)
        tool_name = tool_call.get("name", "")
        tool_category = tool_call.get("category", "")

        embedding: Dict[str, float] = {
            "prompt_length": min(num_chars / 1000.0, 1.0),
            "word_count": min(num_words / 100.0, 1.0),
            "digit_ratio": digit_count / max(num_chars, 1),
            "uppercase_ratio": uppercase_count / max(num_chars, 1),
            "special_char_ratio": special_count / max(num_chars, 1),
            "has_dangerous_keyword": 1.0 if has_dangerous else 0.0,
            "high_risk_score": min(risk_score, 1.0),
            "tool_critical": 1.0 if tool_category in CRITICAL_TOOL_CATEGORIES else 0.0,
            "tool_write_category": 1.0 if tool_category in WRITE_TOOL_CATEGORIES else 0.0,
            "is_production_env": 1.0 if environment == "production" else 0.0,
            "has_arguments": 1.0 if bool(tool_call.get("arguments")) else 0.0,
            "was_blocked": 1.0 if decision == "block" else 0.0,
            "risk_level_critical": 1.0 if risk_score >= 0.9 else 0.0,
            "risk_level_high": 1.0 if 0.7 <= risk_score < 0.9 else 0.0,
            "risk_level_medium": 1.0 if 0.4 <= risk_score < 0.7 else 0.0,
            "num_previous_blocks": min(previous_blocks / 50.0, 1.0),
        }

        return embedding

    def encode_from_record(
        self,
        record: Any,
    ) -> Dict[str, float]:
        prompt = getattr(record, "prompt", "")
        risk_score = getattr(record, "risk_score", 0.0)
        decision = getattr(record, "decision", "allow")

        tool_used = getattr(record, "tool_used", "")
        context = getattr(record, "context", {}) or {}

        tool_call = {
            "name": tool_used,
            "category": context.get("tool_category", ""),
            "arguments": context.get("arguments", {}),
        }

        previous_blocks = context.get("previous_blocks", 0)
        environment = context.get("environment", "development")

        return self.encode(
            prompt=prompt,
            tool_call=tool_call,
            decision=decision,
            risk_score=risk_score,
            environment=environment,
            previous_blocks=previous_blocks,
        )

    def embedding_to_vector(
        self, embedding: Dict[str, float]
    ) -> List[float]:
        return [embedding.get(f, 0.0) for f in EMBEDDING_FEATURES]

    def vector_to_embedding(
        self, vector: List[float]
    ) -> Dict[str, float]:
        return dict(zip(EMBEDDING_FEATURES, vector))

    @property
    def feature_names(self) -> List[str]:
        return list(EMBEDDING_FEATURES)
