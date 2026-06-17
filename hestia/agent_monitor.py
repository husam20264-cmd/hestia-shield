"""
Agent Monitor for Hestia Shield v1.0.0
"""

import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from .models import DecisionType, RiskLevel

logger = logging.getLogger(__name__)


@dataclass
class AgentProfile:
    agent_id: str
    name: str
    allowed_tools: Set[str] = field(default_factory=set)
    blocked_tools: Set[str] = field(default_factory=set)
    risk_level: RiskLevel = RiskLevel.LOW
    total_calls: int = 0
    blocked_calls: int = 0
    last_activity: Optional[datetime] = None
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "allowed_tools": list(self.allowed_tools),
            "blocked_tools": list(self.blocked_tools),
            "risk_level": self.risk_level.value,
            "total_calls": self.total_calls,
            "blocked_calls": self.blocked_calls,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "metadata": self.metadata
        }


class AgentMonitor:
    def __init__(self):
        self.agent_profiles: Dict[str, AgentProfile] = {}
        self.tool_usage: Dict[str, int] = {}
        self.anomalies: List[Dict] = []

    def create_profile(self, agent_id: str, name: str, allowed_tools: Optional[List[str]] = None) -> AgentProfile:
        profile = AgentProfile(
            agent_id=agent_id,
            name=name,
            allowed_tools=set(allowed_tools) if allowed_tools else set()
        )
        self.agent_profiles[agent_id] = profile
        logger.info(f"Created agent profile: {agent_id}")
        return profile

    def get_profile(self, agent_id: str) -> Optional[AgentProfile]:
        return self.agent_profiles.get(agent_id)

    def record_tool_call(self, agent_id: str, tool_name: str, decision: DecisionType):
        if agent_id not in self.agent_profiles:
            logger.warning(f"Unknown agent: {agent_id}")
            return

        profile = self.agent_profiles[agent_id]
        profile.total_calls += 1
        profile.last_activity = datetime.now()

        self.tool_usage[tool_name] = self.tool_usage.get(tool_name, 0) + 1

        if decision in [DecisionType.BLOCK, DecisionType.TERMINATE_SESSION]:
            profile.blocked_calls += 1

            block_ratio = profile.blocked_calls / profile.total_calls
            if block_ratio > 0.3:
                profile.risk_level = RiskLevel.HIGH
                self._record_anomaly(agent_id, "high_block_ratio", block_ratio)
            elif block_ratio > 0.1:
                profile.risk_level = RiskLevel.MEDIUM

        if tool_name in profile.blocked_tools:
            self._record_anomaly(agent_id, "blocked_tool_attempt", {"tool": tool_name})

    def _record_anomaly(self, agent_id: str, anomaly_type: str, details: Dict):
        anomaly = {
            "timestamp": datetime.now().isoformat(),
            "agent_id": agent_id,
            "type": anomaly_type,
            "details": details
        }
        self.anomalies.append(anomaly)
        logger.warning(f"Anomaly detected for agent {agent_id}: {anomaly_type}")

    def get_agent_stats(self, agent_id: str) -> Optional[Dict]:
        profile = self.agent_profiles.get(agent_id)
        if not profile:
            return None

        return {
            "profile": profile.to_dict(),
            "tool_usage": {
                tool: count
                for tool, count in self.tool_usage.items()
            },
            "recent_anomalies": [
                a for a in self.anomalies
                if a["agent_id"] == agent_id
            ][-10:]
        }

    def get_all_agents(self) -> List[Dict]:
        return [p.to_dict() for p in self.agent_profiles.values()]

    def cleanup_inactive(self, threshold_minutes: int = 60):
        from datetime import timedelta
        cutoff = datetime.now() - timedelta(minutes=threshold_minutes)

        inactive = [
            aid for aid, profile in self.agent_profiles.items()
            if profile.last_activity and profile.last_activity < cutoff
        ]

        for aid in inactive:
            del self.agent_profiles[aid]
            logger.info(f"Cleaned up inactive agent: {aid}")

        return len(inactive)