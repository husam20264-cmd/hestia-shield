"""
Strategy Optimizer for Self-Learning Attack Memory
"""

from typing import List, Dict, Any, Optional
from collections import defaultdict
import random

from .attack_memory import AttackMemory, AttackRecord


class StrategyOptimizer:
    """
    محسن استراتيجيات الهجوم بناءً على الذاكرة المتعلمة
    """

    def __init__(self, memory: AttackMemory):
        self.memory = memory
        self.strategy_weights = {
            "aggressive": 0.3,
            "balanced": 0.5,
            "stealth": 0.2,
        }
        self.tool_preferences = defaultdict(float)
        self.pattern_preferences = defaultdict(float)

    def update(self, record: AttackRecord):
        """تحديث الاستراتيجية بناءً على سجل هجوم"""
        tool = record.tool_used or "unknown"
        if record.success:
            self.tool_preferences[tool] += 0.1
        else:
            self.tool_preferences[tool] -= 0.05

        pattern = self._extract_pattern(record)
        if record.success:
            self.pattern_preferences[pattern] += 0.1
        else:
            self.pattern_preferences[pattern] -= 0.05

        if record.success and record.risk_score < 0.3:
            self.strategy_weights["stealth"] += 0.05
        elif record.success and record.risk_score > 0.6:
            self.strategy_weights["aggressive"] += 0.05
        else:
            self.strategy_weights["balanced"] += 0.05

        total = sum(self.strategy_weights.values())
        if total > 0:
            for key in self.strategy_weights:
                self.strategy_weights[key] /= total

    def _extract_pattern(self, record: AttackRecord) -> str:
        """استخراج نمط الهجوم"""
        prompt_words = set(record.prompt.lower().split())
        keywords = [
            "read", "write", "execute", "delete", "modify", "access",
            "send", "upload", "download", "view", "list", "create",
        ]
        found = [kw for kw in keywords if kw in prompt_words]
        return f"{record.tool_used}:{','.join(found) if found else 'generic'}"

    def get_best_strategy(self) -> Dict[str, Any]:
        """الحصول على أفضل استراتيجية حالية"""
        return {
            "weights": dict(self.strategy_weights),
            "top_tools": sorted(
                self.tool_preferences.items(),
                key=lambda x: x[1],
                reverse=True,
            )[:3],
            "top_patterns": sorted(
                self.pattern_preferences.items(),
                key=lambda x: x[1],
                reverse=True,
            )[:3],
        }

    def generate_next_action(self, context: Dict) -> Dict:
        """توليد الإجراء التالي بناءً على الاستراتيجية المحسّنة"""
        best = self.get_best_strategy()

        strategies = list(self.strategy_weights.keys())
        weights = list(self.strategy_weights.values())

        if not strategies or sum(weights) == 0:
            selected_strategy = "balanced"
        else:
            selected_strategy = random.choices(strategies, weights=weights, k=1)[0]

        top_tools = [t[0] for t in best["top_tools"]]
        if top_tools and random.random() < 0.7:
            selected_tool = random.choice(top_tools)
        else:
            selected_tool = None

        return {
            "strategy": selected_strategy,
            "preferred_tool": selected_tool,
            "confidence": sum(weights) / len(weights) if weights else 0.5,
            "tool_preferences": dict(self.tool_preferences),
        }
