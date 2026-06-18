"""
Hestia Shield - Runtime Security for AI Agents
"""

import asyncio
from typing import Dict, Any, Optional

from .models import Decision, DecisionType, RiskLevel, ToolCall, Rule
from .rules_engine import RulesEngine
from .attack_memory import AttackMemory
from .classifier import TextClassifier
from .agent_monitor import AgentMonitor, AgentProfile
from .decision_engine import DecisionEngine
from .version import __version__

__all__ = [
    "HestiaCore",
    "Decision",
    "DecisionType",
    "RiskLevel",
    "ToolCall",
    "Rule",
    "RulesEngine",
    "AttackMemory",
    "TextClassifier",
    "AgentMonitor",
    "AgentProfile",
    "DecisionEngine",
    "__version__",
]


class HestiaCore:
    def __init__(
        self,
        tenant_id: str,
        storage=None,
        enable_monitoring: bool = True
    ):
        self.tenant_id = tenant_id
        self.storage = storage
        self.enable_monitoring = enable_monitoring
        self.decision_engine = DecisionEngine()

    def evaluate_prompt(
        self,
        prompt: str,
        user_id: str,
        model_id: Optional[str] = None,
        context: Optional[Dict] = None
    ) -> Decision:
        return asyncio.run(
            self.decision_engine.evaluate_prompt(
                prompt=prompt,
                user_id=user_id,
                model_id=model_id,
                context=context,
            )
        )

    def evaluate_tool_call(
        self,
        tool_call: ToolCall,
        user_id: str,
        agent_id: Optional[str] = None,
        context: Optional[Dict] = None
    ) -> Decision:
        return asyncio.run(
            self.decision_engine.evaluate_tool_call(
                tool_call=tool_call,
                user_id=user_id,
                agent_id=agent_id,
                context=context,
            )
        )

    def get_stats(self) -> Dict:
        return self.decision_engine.get_stats()