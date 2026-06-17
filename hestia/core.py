"""
Hestia Shield - Runtime Security for AI Agents
"""

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