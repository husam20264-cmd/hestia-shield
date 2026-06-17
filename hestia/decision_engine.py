"""
Decision Engine for Hestia Shield v1.0.0
"""

import time
import logging
from typing import Dict, Any, Optional, List
from .models import Decision, DecisionType, RiskLevel, ToolCall
from .rules_engine import RulesEngine
from .classifier import TextClassifier
from .attack_memory import AttackMemory
from .telemetry import get_tracer, get_meter

logger = logging.getLogger(__name__)
_tracer = get_tracer("hestia.decision_engine")
_meter = get_meter("hestia.decision_engine")

_decision_counter = _meter.create_counter("decisions.total")
_latency_histogram = _meter.create_histogram("decisions.latency")


class DecisionEngine:
    def __init__(
        self,
        rules_engine: Optional[RulesEngine] = None,
        classifier: Optional[TextClassifier] = None,
        attack_memory: Optional[AttackMemory] = None
    ):
        self.rules_engine = rules_engine or RulesEngine()
        self.classifier = classifier or TextClassifier()
        self.attack_memory = attack_memory or AttackMemory()
        self.component_times: Dict[str, float] = {}

    async def evaluate_prompt(
        self,
        prompt: str,
        user_id: str,
        model_id: Optional[str] = None,
        context: Optional[Dict] = None
    ) -> Decision:
        start_time = time.perf_counter()
        self.component_times = {}

        with _tracer.start_as_current_span("evaluate_prompt") as span:
            span.set_attribute("prompt.length", len(prompt))
            span.set_attribute("user_id", user_id)
            span.set_attribute("model_id", model_id or "")

            context = context or {}
            context["text"] = prompt

            rule_decision = self._check_rules(context)
            if rule_decision:
                span.set_attribute("blocked_by", "rules")
                span.set_attribute("decision", rule_decision.decision.value)
                span.set_attribute("risk_score", rule_decision.risk_score)
                _decision_counter.add(1, {"decision": rule_decision.decision.value})
                return rule_decision

            risk_level, risk_score, triggered = self.classifier.classify(prompt)
            self.component_times["classification"] = time.perf_counter() - start_time

            if risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                decision = Decision(
                    decision=DecisionType.BLOCK,
                    risk_score=risk_score,
                    reason=f"High-risk content detected: {', '.join(triggered)}",
                    details={
                        "risk_level": risk_level.value,
                        "triggered_keywords": triggered,
                        "fast_path": True
                    }
                )
                span.set_attribute("decision", "block")
                span.set_attribute("risk_level", risk_level.value)
                span.set_attribute("fast_path", True)
                _decision_counter.add(1, {"decision": "block"})
                return decision

            user_profile = self.attack_memory.get_user_risk_profile(user_id)
            self.component_times["attack_memory"] = time.perf_counter() - start_time

            if user_profile["risk_score"] > 0.7:
                decision = Decision(
                    decision=DecisionType.HUMAN_REVIEW,
                    risk_score=user_profile["risk_score"],
                    reason="User has high-risk profile",
                    details={
                        "user_risk_score": user_profile["risk_score"],
                        "blocked_events": user_profile["blocked_events"],
                        "patterns": user_profile["attack_patterns"]
                    }
                )
                span.set_attribute("decision", "human_review")
                span.set_attribute("user_risk_score", user_profile["risk_score"])
                _decision_counter.add(1, {"decision": "human_review"})
                return decision

            total_time = (time.perf_counter() - start_time) * 1000

            decision = Decision(
                decision=DecisionType.ALLOW,
                risk_score=risk_score,
                reason="Request passed all checks",
                details={
                    "risk_level": risk_level.value,
                    "evaluation_ms": total_time,
                    "component_times": dict(self.component_times),
                    "fast_path": True
                }
            )
            span.set_attribute("decision", "allow")
            span.set_attribute("risk_score", risk_score)
            span.set_attribute("evaluation_ms", total_time)
            span.set_attribute("fast_path", True)
            _decision_counter.add(1, {"decision": "allow"})
            _latency_histogram.record(total_time, {"decision": "allow"})

            return decision

    async def evaluate_tool_call(
        self,
        tool_call: ToolCall,
        user_id: str,
        agent_id: Optional[str] = None,
        context: Optional[Dict] = None
    ) -> Decision:
        start_time = time.perf_counter()
        self.component_times = {}

        with _tracer.start_as_current_span("evaluate_tool_call") as span:
            span.set_attribute("tool_name", tool_call.name)
            span.set_attribute("tool_category", tool_call.category)
            span.set_attribute("user_id", user_id)
            span.set_attribute("agent_id", agent_id or "")

            context = context or {}
            context["tool_name"] = tool_call.name
            context["tool_category"] = tool_call.category
            context["environment"] = tool_call.environment

            rule_decision = self._check_rules(context)
            if rule_decision:
                span.set_attribute("blocked_by", "rules")
                span.set_attribute("decision", rule_decision.decision.value)
                _decision_counter.add(1, {"decision": rule_decision.decision.value})
                return rule_decision

            if tool_call.is_critical:
                if tool_call.environment == "production":
                    decision = Decision(
                        decision=DecisionType.HUMAN_REVIEW,
                        risk_score=0.8,
                        reason="Critical tool in production requires review",
                        details={
                            "tool_name": tool_call.name,
                            "environment": tool_call.environment,
                            "fast_path": False
                        }
                    )
                    span.set_attribute("decision", "human_review")
                    span.set_attribute("is_critical", True)
                    _decision_counter.add(1, {"decision": "human_review"})
                    return decision

            total_time = (time.perf_counter() - start_time) * 1000

            decision = Decision(
                decision=DecisionType.ALLOW,
                risk_score=0.1,
                reason="Tool call approved",
                details={
                    "tool_name": tool_call.name,
                    "evaluation_ms": total_time,
                    "component_times": dict(self.component_times),
                    "fast_path": True
                }
            )
            span.set_attribute("decision", "allow")
            span.set_attribute("evaluation_ms", total_time)
            span.set_attribute("fast_path", True)
            _decision_counter.add(1, {"decision": "allow"})
            _latency_histogram.record(total_time, {"decision": "allow"})

            return decision

    def _check_rules(self, context: Dict) -> Optional[Decision]:
        start_time = time.perf_counter()
        decision = self.rules_engine.evaluate(context)
        self.component_times["rules"] = time.perf_counter() - start_time
        return decision

    def get_stats(self) -> Dict:
        return {
            "component_times": dict(self.component_times),
            "total_evaluations": sum(
                self.attack_memory.get_stats().get("total_events", 0)
                for _ in range(1)
            )
        }