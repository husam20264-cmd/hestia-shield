"""
Data models for Hestia Shield - v1.0.0
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
from datetime import datetime
import json


class DecisionType(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    DEGRADE = "degrade"
    SANDBOX = "sandbox"
    HUMAN_REVIEW = "human_review"
    HONEYPOT = "honeypot"
    TERMINATE_SESSION = "terminate_session"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Decision:
    """قرار أمني"""
    decision: DecisionType
    risk_score: float
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.decision == DecisionType.ALLOW

    @property
    def is_blocked(self) -> bool:
        """تحقق آمن من الحظر"""
        blocked = {DecisionType.BLOCK}
        if hasattr(DecisionType, "TERMINATE_SESSION"):
            blocked.add(DecisionType.TERMINATE_SESSION)
        return self.decision in blocked

    def to_dict(self) -> Dict:
        return {
            "decision": self.decision.value,
            "risk_score": self.risk_score,
            "reason": self.reason,
            "details": self.details
        }


@dataclass
class ToolCall:
    """استدعاء أداة"""
    name: str
    category: str
    target: Dict[str, str]
    arguments: Dict[str, Any]
    environment: str = "development"

    @property
    def is_critical(self) -> bool:
        return self.category in ["execute", "finance", "admin"] or \
               self.name in ["shell", "credential_access", "admin_api"]


@dataclass
class Rule:
    """قاعدة أمان"""
    id: str
    name: str
    type: str
    conditions: Dict[str, Any]
    action: DecisionType
    priority: int = 0
    enabled: bool = True
    description: str = ""

    def matches(self, context: Dict) -> bool:
        if self.type == "block_keywords":
            text = context.get("text", "").lower()
            keywords = self.conditions.get("keywords", [])
            return any(kw.lower() in text for kw in keywords)

        if self.type == "block_tools":
            tool_name = context.get("tool_name", "")
            blocked = self.conditions.get("tools", [])
            return tool_name in blocked

        if self.type == "allowlist":
            tool_name = context.get("tool_name", "")
            allowed = self.conditions.get("tools", [])
            return tool_name not in allowed

        if self.type == "custom":
            for key, expected in self.conditions.items():
                actual = context.get(key)
                if isinstance(expected, list):
                    if actual not in expected:
                        return False
                else:
                    if actual != expected:
                        return False
            return True

        return False


@dataclass
class AttackPattern:
    """نمط هجوم"""
    id: str
    type: str
    severity: RiskLevel
    indicators: List[str]
    recommended_action: DecisionType
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def matches(self, text: str) -> float:
        text_lower = text.lower()
        matches = sum(1 for ind in self.indicators if ind.lower() in text_lower)
        if matches == 0:
            return 0.0
        return min(matches / len(self.indicators), 1.0)


@dataclass
class SecurityEvent:
    """حدث أمني"""
    id: str
    tenant_id: str
    user_id: str
    model_id: Optional[str]
    event_type: str
    input_text: Optional[str] = None
    tool_call: Optional[Dict] = None
    decision: Optional[Decision] = None
    risk_score: float = 0.0
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "event_type": self.event_type,
            "risk_score": self.risk_score,
            "decision": self.decision.to_dict() if self.decision else None,
            "created_at": self.created_at.isoformat()
        }


class WebhookEventType(str, Enum):
    ALL = "all"
    BLOCK = "block"
    HUMAN_REVIEW = "human_review"
    ANOMALY = "anomaly"
    ALERT = "alert"
    TOOL_CALL = "tool_call"
    PROMPT = "prompt"


@dataclass
class WebhookSubscription:
    id: str
    tenant_id: str
    url: str
    events: List[str]
    secret: Optional[str] = None
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    last_triggered_at: Optional[datetime] = None
    failure_count: int = 0

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "url": self.url,
            "events": self.events,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "last_triggered_at": self.last_triggered_at.isoformat() if self.last_triggered_at else None,
            "failure_count": self.failure_count
        }


@dataclass
class WebhookEvent:
    id: str
    event_type: str
    tenant_id: str
    timestamp: str
    data: Dict[str, Any]

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "event_type": self.event_type,
            "tenant_id": self.tenant_id,
            "timestamp": self.timestamp,
            "data": self.data
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())