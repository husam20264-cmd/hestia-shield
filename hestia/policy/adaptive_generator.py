"""
Adaptive Policy Generator for Hestia Shield v3.0.0

Analyzes attack memory to generate, refine, and apply security policies
automatically. The system writes its own rules based on observed patterns.
"""

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from collections import Counter, defaultdict

from ..models import Rule, DecisionType
from ..rules_engine import RulesEngine
from ..memory.attack_memory import AttackMemory, AttackRecord
from ..memory.pattern_analyzer import PatternAnalyzer

logger = logging.getLogger(__name__)

_STOP_WORDS = frozenset({
    "the", "and", "for", "that", "with", "this", "from", "are", "was",
    "were", "been", "have", "has", "had", "will", "would", "could",
    "should", "shall", "may", "might", "must", "does", "did", "what",
    "which", "when", "where", "who", "whom", "how", "then", "than",
    "can", "not", "but", "just", "into", "over", "also", "very",
    "some", "them", "only", "about", "here", "there", "where", "why",
    "please", "need", "want", "like", "using", "your", "able",
})


@dataclass
class GeneratedPolicy:
    policy_id: str
    rules: List[Rule]
    risk_thresholds: Dict[str, float]
    tool_restrictions: Dict[str, str]
    confidence: float
    source: str
    timestamp: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "policy_id": self.policy_id,
            "rules": [
                {
                    "id": r.id,
                    "name": r.name,
                    "type": r.type,
                    "conditions": r.conditions,
                    "action": r.action.value,
                    "priority": r.priority,
                    "enabled": r.enabled,
                    "description": r.description,
                }
                for r in self.rules
            ],
            "risk_thresholds": self.risk_thresholds,
            "tool_restrictions": self.tool_restrictions,
            "confidence": self.confidence,
            "source": self.source,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


class AdaptivePolicyGenerator:
    def __init__(
        self,
        memory: AttackMemory,
        min_samples: int = 5,
        block_threshold: float = 0.85,
        review_threshold: float = 0.65,
        keyword_confidence_min: float = 0.6,
        existing_keywords: Optional[set] = None,
    ):
        self.memory = memory
        self.analyzer = PatternAnalyzer()
        self.min_samples = min_samples
        self.block_threshold = block_threshold
        self.review_threshold = review_threshold
        self.keyword_confidence_min = keyword_confidence_min
        self._existing_keywords = existing_keywords or set()
        self.generation_count = 0
        self.last_generated: Optional[GeneratedPolicy] = None

    def generate(self, limit: int = 200) -> GeneratedPolicy:
        self.generation_count += 1

        ids = self.memory.get_recent(limit)
        records = [self.memory.get(rid) for rid in ids]
        records = [r for r in records if r is not None]

        rules: List[Rule] = []
        new_keywords: List[str] = []
        tool_restrictions: Dict[str, str] = {}
        metadata: Dict[str, Any] = {}

        keyword_rules, extracted_keywords = self._generate_keyword_rules(records)
        rules.extend(keyword_rules)
        new_keywords.extend(extracted_keywords)

        tool_rules, tool_restrictions = self._generate_tool_rules(records)
        rules.extend(tool_rules)

        risk_thresholds = self._compute_risk_thresholds(records)

        metadata["records_analyzed"] = len(records)
        metadata["keyword_extraction_count"] = len(new_keywords)
        metadata["tool_restriction_count"] = len(tool_restrictions)

        confidence = self._compute_confidence(records)

        policy = GeneratedPolicy(
            policy_id=f"policy_{uuid.uuid4().hex[:12]}",
            rules=rules,
            risk_thresholds=risk_thresholds,
            tool_restrictions=tool_restrictions,
            confidence=confidence,
            source="adaptive_generator",
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
            metadata=metadata,
        )

        self.last_generated = policy
        logger.info(
            "Generated policy %s: %d rules, confidence=%.2f, records=%d",
            policy.policy_id,
            len(rules),
            confidence,
            len(records),
        )

        return policy

    def _generate_keyword_rules(
        self, records: List[AttackRecord]
    ) -> tuple:
        if len(records) < self.min_samples:
            return [], []

        blocked = [r for r in records if r.was_blocked]
        keyword_counter: Counter = Counter()

        for record in blocked:
            words = record.prompt.lower().split()
            meaningful = [
                w
                for w in words
                if len(w) > 3 and w not in _STOP_WORDS
            ]
            keyword_counter.update(meaningful)

        high_risk_keywords = []
        existing_keywords = self._get_existing_keywords()

        for keyword, count in keyword_counter.most_common(20):
            if count < 2:
                break
            if keyword in existing_keywords:
                continue
            total_with_keyword = sum(
                1
                for r in records
                if keyword in r.prompt.lower()
            )
            blocked_with_keyword = sum(
                1
                for r in blocked
                if keyword in r.prompt.lower()
            )
            if total_with_keyword == 0:
                continue
            block_rate = blocked_with_keyword / total_with_keyword
            if block_rate >= self.keyword_confidence_min:
                high_risk_keywords.append(keyword)

        rules = []
        if high_risk_keywords:
            rule = Rule(
                id=f"adaptive_kw_{uuid.uuid4().hex[:8]}",
                name=f"Adaptive keyword block (gen #{self.generation_count})",
                type="block_keywords",
                conditions={"keywords": high_risk_keywords},
                action=DecisionType.BLOCK,
                priority=5,
                enabled=True,
                description=f"Auto-generated from {len(blocked)} blocked attacks",
            )
            rules.append(rule)

        return rules, high_risk_keywords

    def _generate_tool_rules(
        self, records: List[AttackRecord]
    ) -> tuple:
        if len(records) < self.min_samples:
            return [], {}

        tool_stats: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"total": 0, "blocked": 0, "high_risk": 0}
        )

        for record in records:
            tool = record.tool_used or "unknown"
            tool_stats[tool]["total"] += 1
            if record.was_blocked:
                tool_stats[tool]["blocked"] += 1
            if record.risk_score >= 0.7:
                tool_stats[tool]["high_risk"] += 1

        block_tools: List[str] = []
        restrict_tools: List[str] = []
        tool_restrictions: Dict[str, str] = {}

        for tool, stats in tool_stats.items():
            if stats["total"] < self.min_samples:
                continue
            block_rate = stats["blocked"] / stats["total"]
            high_risk_rate = stats["high_risk"] / stats["total"]

            if block_rate >= self.block_threshold:
                block_tools.append(tool)
                tool_restrictions[tool] = "blocked"
            elif block_rate >= self.review_threshold:
                restrict_tools.append(tool)
                tool_restrictions[tool] = "requires_review"

            if high_risk_rate >= 0.5 and tool not in tool_restrictions:
                tool_restrictions[tool] = "high_risk_monitor"
                if tool not in restrict_tools:
                    restrict_tools.append(tool)

        rules = []

        if block_tools:
            rules.append(
                Rule(
                    id=f"adaptive_tool_block_{uuid.uuid4().hex[:8]}",
                    name=f"Adaptive tool block (gen #{self.generation_count})",
                    type="block_tools",
                    conditions={"tools": block_tools},
                    action=DecisionType.BLOCK,
                    priority=8,
                    enabled=True,
                    description=f"Auto-blocked tools with >={self.block_threshold:.0%} block rate",
                )
            )

        if restrict_tools:
            rules.append(
                Rule(
                    id=f"adaptive_tool_review_{uuid.uuid4().hex[:8]}",
                    name=f"Adaptive tool review (gen #{self.generation_count})",
                    type="block_tools",
                    conditions={"tools": restrict_tools},
                    action=DecisionType.HUMAN_REVIEW,
                    priority=3,
                    enabled=True,
                    description=f"Auto-review tools with >={self.review_threshold:.0%} block rate",
                )
            )

        return rules, tool_restrictions

    def _compute_risk_thresholds(self, records: List[AttackRecord]) -> Dict[str, float]:
        if not records:
            return {
                "block": self.block_threshold,
                "human_review": self.review_threshold,
            }

        blocked = [r for r in records if r.was_blocked]
        allowed = [r for r in records if not r.was_blocked]

        avg_blocked_risk = (
            sum(r.risk_score for r in blocked) / len(blocked)
            if blocked
            else 0.8
        )
        avg_allowed_risk = (
            sum(r.risk_score for r in allowed) / len(allowed)
            if allowed
            else 0.2
        )

        midpoint = (avg_blocked_risk + avg_allowed_risk) / 2
        block_threshold = max(
            self.block_threshold,
            midpoint + (avg_blocked_risk - midpoint) * 0.3,
        )
        review_threshold = max(
            self.review_threshold,
            midpoint - (midpoint - avg_allowed_risk) * 0.3,
        )

        block_threshold = min(block_threshold, 0.99)
        review_threshold = min(review_threshold, block_threshold - 0.1)
        review_threshold = max(review_threshold, 0.3)

        return {
            "block": round(block_threshold, 3),
            "human_review": round(review_threshold, 3),
        }

    def _compute_confidence(self, records: List[AttackRecord]) -> float:
        if len(records) < self.min_samples:
            return 0.1
        confidence = min(len(records) / 50.0, 1.0)
        blocked = [r for r in records if r.was_blocked]
        if blocked:
            block_rate = len(blocked) / len(records)
            confidence *= (0.5 + 0.5 * block_rate)
        return round(min(confidence, 1.0), 3)

    def _get_existing_keywords(self) -> set:
        return self._existing_keywords

    def set_existing_keywords(self, keywords: set) -> None:
        self._existing_keywords = keywords

    def generate_from_lessons(self, lessons: Dict) -> Dict[str, Any]:
        """
        Generate policy updates from learned lessons.
        Called by SelfLearner._update_strategy().
        """
        policy_update = {
            "new_block_keywords": [],
            "tool_restrictions": {},
            "risk_thresholds": {},
            "suggested_actions": [],
        }

        failure_patterns = lessons.get("failure_patterns", [])
        for pattern in failure_patterns[:5]:
            if pattern.get("failure_rate", 0) > 0.7:
                pattern_str = pattern.get("pattern", "")
                if ":" in pattern_str:
                    keywords = pattern_str.split(":")[-1].split(",")
                    policy_update["new_block_keywords"].extend(
                        [kw for kw in keywords if kw and kw != "generic"]
                    )

        worst_tools = lessons.get("worst_tools", [])
        for tool_data in worst_tools[:5]:
            if tool_data.get("success_rate", 1) < 0.3:
                tool_name = tool_data.get("tool", "")
                if tool_name:
                    policy_update["tool_restrictions"][tool_name] = "human_review"

        overall_success_rate = lessons.get("overall_success_rate", 0.5)
        if overall_success_rate < 0.3:
            policy_update["risk_thresholds"]["block"] = 0.75
            policy_update["risk_thresholds"]["human_review"] = 0.55
        elif overall_success_rate > 0.7:
            policy_update["risk_thresholds"]["block"] = 0.90
            policy_update["risk_thresholds"]["human_review"] = 0.70

        if policy_update["new_block_keywords"]:
            unique_keywords = list(set(policy_update["new_block_keywords"]))[:10]
            policy_update["suggested_actions"].append(
                f"Review blocking rules for: {', '.join(unique_keywords)}"
            )
        if policy_update["tool_restrictions"]:
            policy_update["suggested_actions"].append(
                f"Apply tool restrictions: {', '.join(policy_update['tool_restrictions'].keys())}"
            )
        if not policy_update["suggested_actions"]:
            policy_update["suggested_actions"].append("No immediate policy changes recommended")

        return policy_update

    def get_stats(self) -> Dict[str, Any]:
        return {
            "generation_count": self.generation_count,
            "last_policy_id": self.last_generated.policy_id if self.last_generated else None,
            "last_confidence": self.last_generated.confidence if self.last_generated else 0,
            "min_samples": self.min_samples,
            "block_threshold": self.block_threshold,
            "review_threshold": self.review_threshold,
        }


class PolicyApplier:
    def __init__(
        self,
        rules_engine: RulesEngine,
        auto_apply: bool = False,
        dry_run: bool = False,
    ):
        self.rules_engine = rules_engine
        self.auto_apply = auto_apply
        self.dry_run = dry_run
        self.applied_policies: List[Dict] = []
        self.pending_policies: List[GeneratedPolicy] = []

    def apply(self, policy: GeneratedPolicy) -> Dict[str, Any]:
        if not policy.rules:
            return {
                "status": "skipped",
                "reason": "No rules in policy",
                "rules_applied": 0,
            }

        if self.dry_run:
            self.pending_policies.append(policy)
            return {
                "status": "dry_run",
                "policy_id": policy.policy_id,
                "rules_preview": len(policy.rules),
                "confidence": policy.confidence,
            }

        if not self.auto_apply:
            self.pending_policies.append(policy)
            return {
                "status": "pending_approval",
                "policy_id": policy.policy_id,
                "rules_count": len(policy.rules),
                "confidence": policy.confidence,
            }

        return self._apply_rules(policy)

    def approve_pending(self, policy_id: str) -> Dict[str, Any]:
        policy = None
        for i, p in enumerate(self.pending_policies):
            if p.policy_id == policy_id:
                policy = self.pending_policies.pop(i)
                break

        if not policy:
            return {"status": "not_found", "policy_id": policy_id}

        return self._apply_rules(policy)

    def reject_pending(self, policy_id: str) -> Dict[str, Any]:
        for i, p in enumerate(self.pending_policies):
            if p.policy_id == policy_id:
                self.pending_policies.pop(i)
                return {"status": "rejected", "policy_id": policy_id}
        return {"status": "not_found", "policy_id": policy_id}

    def _apply_rules(self, policy: GeneratedPolicy) -> Dict[str, Any]:
        existing_ids = {r.id for r in self.rules_engine.rules}
        applied_count = 0
        applied_rules = []

        for rule in policy.rules:
            if rule.id in existing_ids:
                self.rules_engine.remove_rule(rule.id)
            self.rules_engine.add_rule(rule)
            applied_count += 1
            applied_rules.append(rule.id)

        record = {
            "status": "applied",
            "policy_id": policy.policy_id,
            "rules_applied": applied_count,
            "rule_ids": applied_rules,
            "confidence": policy.confidence,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "risk_thresholds": policy.risk_thresholds,
            "tool_restrictions": policy.tool_restrictions,
        }
        self.applied_policies.append(record)

        logger.info(
            "Applied policy %s: %d rules, confidence=%.2f",
            policy.policy_id,
            applied_count,
            policy.confidence,
        )

        return record

    def get_pending(self) -> List[Dict]:
        return [p.to_dict() for p in self.pending_policies]

    def get_applied(self) -> List[Dict]:
        return list(self.applied_policies)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "auto_apply": self.auto_apply,
            "dry_run": self.dry_run,
            "pending_count": len(self.pending_policies),
            "applied_count": len(self.applied_policies),
        }
