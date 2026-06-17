"""
Rules Engine for Hestia Shield v1.0.0
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from .models import Rule, Decision, DecisionType

logger = logging.getLogger(__name__)


class RulesEngine:
    def __init__(self, rules: Optional[List[Rule]] = None):
        self.rules: List[Rule] = rules or []
        self._rules_by_id: Dict[str, Rule] = {}
        for rule in self.rules:
            self._rules_by_id[rule.id] = rule

    def add_rule(self, rule: Rule):
        self.rules.append(rule)
        self._rules_by_id[rule.id] = rule

    def remove_rule(self, rule_id: str):
        if rule_id in self._rules_by_id:
            rule = self._rules_by_id.pop(rule_id)
            self.rules.remove(rule)

    def evaluate(self, context: Dict) -> Optional[Decision]:
        enabled_rules = [r for r in self.rules if r.enabled]
        sorted_rules = sorted(enabled_rules, key=lambda r: r.priority, reverse=True)

        for rule in sorted_rules:
            if rule.matches(context):
                return Decision(
                    decision=rule.action,
                    risk_score=1.0 if rule.action == DecisionType.BLOCK else 0.5,
                    reason=f"Rule matched: {rule.name}",
                    details={"rule_id": rule.id, "rule_name": rule.name}
                )

        return None

    @classmethod
    def load_from_file(cls, file_path: str) -> "RulesEngine":
        with open(file_path, 'r') as f:
            data = json.load(f)

        rules = []
        for r in data.get("rules", []):
            rules.append(Rule(
                id=r["id"],
                name=r.get("name", r["id"]),
                type=r["type"],
                conditions=r["conditions"],
                action=DecisionType(r["action"]),
                priority=r.get("priority", 0),
                enabled=r.get("enabled", True),
                description=r.get("description", "")
            ))

        return cls(rules)

    def to_dict(self) -> Dict:
        return {
            "rules": [
                {
                    "id": r.id,
                    "name": r.name,
                    "type": r.type,
                    "conditions": r.conditions,
                    "action": r.action.value,
                    "priority": r.priority,
                    "enabled": r.enabled,
                    "description": r.description
                }
                for r in self.rules
            ]
        }