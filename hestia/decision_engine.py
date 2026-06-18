"""
Decision Engine for Hestia Shield v1.0.0
"""

import os
import uuid
import time
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path
from .models import Decision, DecisionType, RiskLevel, ToolCall
from .rules_engine import RulesEngine
from .classifier import TextClassifier
from .attack_memory import AttackMemory
from .telemetry import get_tracer, get_meter

try:
    from .ml.inference import ThreatInference
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

try:
    from .memory.attack_memory import AttackMemory as SLAttackMemory, AttackRecord
    from .memory.self_learner import SelfLearner
    from .memory.strategy_optimizer import StrategyOptimizer
    SL_MEMORY_AVAILABLE = True
except ImportError:
    SL_MEMORY_AVAILABLE = False

try:
    from .policy.adaptive_generator import AdaptivePolicyGenerator, PolicyApplier
    POLICY_AVAILABLE = True
except ImportError:
    POLICY_AVAILABLE = False

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

        model_path = os.getenv("HESTIA_ML_MODEL_PATH", "")
        if ML_AVAILABLE and model_path and Path(model_path).exists():
            self.ml_inference = ThreatInference(Path(model_path))
            self.ml_enabled = True
        else:
            self.ml_inference = None
            self.ml_enabled = False

        if SL_MEMORY_AVAILABLE:
            self.sl_memory = SLAttackMemory()
            self.policy_generator = AdaptivePolicyGenerator(self.sl_memory) if POLICY_AVAILABLE else None
            self.self_learner = SelfLearner(self.sl_memory, self.policy_generator)
            self.strategy_optimizer = StrategyOptimizer(self.sl_memory)
            self.learning_enabled = True
        else:
            self.sl_memory = None
            self.self_learner = None
            self.strategy_optimizer = None
            self.learning_enabled = False
            self.policy_generator = None

        self.policy_auto_apply = os.getenv("HESTIA_POLICY_AUTO_APPLY", "false").lower() == "true"
        self.policy_generation_interval = int(os.getenv("HESTIA_POLICY_GEN_INTERVAL", "10"))

        if POLICY_AVAILABLE and self.learning_enabled and self.policy_generator:
            self.policy_applier = PolicyApplier(
                self.rules_engine,
                auto_apply=self.policy_auto_apply,
            )
            self.policy_enabled = True
        else:
            self.policy_applier = None
            self.policy_enabled = False

        self._decision_count = 0

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

            if self.ml_enabled and self.ml_inference:
                ml_risk, ml_threat = self.ml_inference.evaluate(
                    prompt=prompt,
                    tool_call={},
                    action_history=[],
                )
                self.component_times["ml_inference"] = time.perf_counter() - start_time

                if ml_threat:
                    decision = Decision(
                        decision=DecisionType.BLOCK,
                        risk_score=ml_risk,
                        reason=f"ML-based detection: {ml_risk:.2f} risk score",
                        details={
                            "ml_risk": ml_risk,
                            "source": "ml",
                            "fast_path": False,
                        },
                    )
                    span.set_attribute("decision", "block")
                    span.set_attribute("ml_risk", ml_risk)
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

            self._record_decision(decision, prompt)
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

            if self.ml_enabled and self.ml_inference:
                ml_risk, ml_threat = self.ml_inference.evaluate(
                    prompt="",
                    tool_call={"name": tool_call.name, "category": tool_call.category, "target": {}, "arguments": {}},
                    action_history=[],
                )
                self.component_times["ml_inference"] = time.perf_counter() - start_time

                if ml_threat:
                    decision = Decision(
                        decision=DecisionType.BLOCK,
                        risk_score=ml_risk,
                        reason=f"ML detected malicious tool call: {tool_call.name}",
                        details={
                            "ml_risk": ml_risk,
                            "tool_name": tool_call.name,
                            "source": "ml",
                            "fast_path": False,
                        },
                    )
                    span.set_attribute("decision", "block")
                    span.set_attribute("ml_risk", ml_risk)
                    _decision_counter.add(1, {"decision": "block"})
                    return decision

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

            self._record_decision(decision, "", tool_call.name)
            return decision

    def _check_rules(self, context: Dict) -> Optional[Decision]:
        start_time = time.perf_counter()
        decision = self.rules_engine.evaluate(context)
        self.component_times["rules"] = time.perf_counter() - start_time
        return decision

    def _record_decision(
        self, decision: Decision, prompt: str, tool_name: str = ""
    ):
        """Record decision in self-learning memory"""
        if not self.learning_enabled or not self.sl_memory:
            return

        record = AttackRecord(
            id=str(uuid.uuid4()),
            prompt=prompt,
            tool_used=tool_name,
            target="",
            was_blocked=decision.decision
            in [DecisionType.BLOCK, DecisionType.TERMINATE_SESSION],
            risk_score=decision.risk_score,
            decision=decision.decision.value,
            response=decision.reason,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
            context={},
            success=decision.decision == DecisionType.ALLOW,
        )

        self.sl_memory.store(record)

        if self.strategy_optimizer:
            self.strategy_optimizer.update(record)

        self._decision_count += 1

        if self._decision_count % 5 == 0:
            if self.self_learner:
                self.self_learner.learn_from_history(limit=50)

        if self.policy_enabled and self.policy_generator and self.policy_applier:
            if self._decision_count % self.policy_generation_interval == 0:
                try:
                    policy = self.policy_generator.generate(limit=100)
                    if policy.rules:
                        self.policy_applier.apply(policy)
                except Exception as e:
                    logger.warning("Adaptive policy generation failed: %s", e)

    def get_stats(self) -> Dict:
        stats = {
            "component_times": dict(self.component_times),
            "total_evaluations": sum(
                self.attack_memory.get_stats().get("total_events", 0)
                for _ in range(1)
            ),
        }
        if self.sl_memory:
            stats["self_learning"] = self.sl_memory.get_stats()
        if self.policy_enabled and self.policy_generator:
            stats["adaptive_policy"] = self.policy_generator.get_stats()
            if self.policy_applier:
                stats["adaptive_policy"].update(self.policy_applier.get_stats())
        return stats