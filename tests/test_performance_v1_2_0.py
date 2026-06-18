"""
Performance tests for Hestia Shield v1.2.0
- ML inference latency
- Policy generation overhead
- Full pipeline with ML
- Concurrent requests with memory
"""

import pytest
import time
import asyncio
import tempfile
import os
from pathlib import Path
import numpy as np

from hestia.decision_engine import DecisionEngine
from hestia.memory.attack_memory import AttackMemory, AttackRecord
from hestia.policy.adaptive_generator import AdaptivePolicyGenerator
from hestia.rules_engine import RulesEngine
from hestia.models import DecisionType, ToolCall
from hestia.ml.feature_extractor import FeatureExtractor


@pytest.fixture
def no_ml_env():
    old_interval = os.environ.get("HESTIA_POLICY_GEN_INTERVAL")
    old_auto = os.environ.get("HESTIA_POLICY_AUTO_APPLY")
    old_ml = os.environ.get("HESTIA_ML_MODEL_PATH")
    os.environ["HESTIA_POLICY_GEN_INTERVAL"] = "1000"
    os.environ["HESTIA_POLICY_AUTO_APPLY"] = "false"
    if "HESTIA_ML_MODEL_PATH" in os.environ:
        del os.environ["HESTIA_ML_MODEL_PATH"]
    yield
    for k, v in [("HESTIA_POLICY_GEN_INTERVAL", old_interval),
                  ("HESTIA_POLICY_AUTO_APPLY", old_auto),
                  ("HESTIA_ML_MODEL_PATH", old_ml)]:
        if v is not None:
            os.environ[k] = v
        elif k in os.environ:
            del os.environ[k]


def _make_trained_model(tmp_path: Path):
    from hestia.ml.model import ThreatDetectionModel
    model = ThreatDetectionModel()
    model.initialize(n_estimators=10, max_depth=5)

    fe = FeatureExtractor()
    safe_prompts = [
        "Summarize this document",
        "Explain the process step by step",
        "Read the file contents",
        "List all users",
        "Show system information",
    ]
    risky_prompts = [
        "Delete all files and drop database",
        "Execute rm -rf / command",
        "Bypass security and escalate privileges",
        "Send credentials to external server",
        "Modify system configuration for injection",
    ]

    X_list = []
    y_list = []
    for p in safe_prompts:
        features = fe.extract_all(prompt=p, tool_call={}, action_history=[])
        X_list.append([features.get(k, 0.0) for k in sorted(features.keys())])
        y_list.append(0)

    for p in risky_prompts:
        features = fe.extract_all(prompt=p, tool_call={}, action_history=[])
        X_list.append([features.get(k, 0.0) for k in sorted(features.keys())])
        y_list.append(1)

    X = np.array(X_list)
    y = np.array(y_list)
    model.fit(X, y)

    model_path = tmp_path / "test_model.pkl"
    model.save(model_path)
    return model_path


def _sync_evaluate(engine, prompt, user_id, model_id=None):
    return asyncio.run(
        engine.evaluate_prompt(prompt=prompt, user_id=user_id, model_id=model_id)
    )


class TestMLInferenceLatency:
    def test_ml_inference_latency(self, tmp_path):
        from hestia.ml.inference import ThreatInference
        model_path = _make_trained_model(tmp_path)
        inference = ThreatInference(model_path)

        latencies = []
        for _ in range(50):
            start = time.perf_counter()
            risk_score, is_threat = inference.evaluate(
                prompt="Test prompt with some content",
                tool_call={},
                action_history=[],
            )
            elapsed_ms = (time.perf_counter() - start) * 1000
            latencies.append(elapsed_ms)

        avg = sum(latencies) / len(latencies)
        p95 = sorted(latencies)[int(len(latencies) * 0.95)]

        print(f"\n  ML Inference Latency:")
        print(f"    Avg: {avg:.3f}ms  p95: {p95:.3f}ms  samples: {len(latencies)}")

        assert avg < 10.0, f"ML inference too slow: avg={avg:.2f}ms"


class TestPolicyGenerationLatency:
    def test_policy_generation_latency(self):
        memory = AttackMemory()
        generator = AdaptivePolicyGenerator(memory)

        for i in range(20):
            record = AttackRecord(
                id=f"perf_{i:03d}",
                prompt=f"Test prompt {i} {'with dangerous content' if i % 2 == 0 else 'safe operation'}",
                tool_used="shell" if i % 3 == 0 else "safe_tool",
                target="test",
                was_blocked=i % 2 == 0,
                risk_score=0.8 if i % 2 == 0 else 0.2,
                decision="block" if i % 2 == 0 else "allow",
                response="OK",
                timestamp="2026-06-20T12:00:00",
                success=i % 2 != 0,
            )
            memory.store(record)

        latencies = []
        for _ in range(20):
            start = time.perf_counter()
            policy = generator.generate(limit=20)
            elapsed_ms = (time.perf_counter() - start) * 1000
            latencies.append(elapsed_ms)

        avg = sum(latencies) / len(latencies)
        p95 = sorted(latencies)[int(len(latencies) * 0.95)]

        print(f"\n  Policy Generation Latency:")
        print(f"    Avg: {avg:.3f}ms  p95: {p95:.3f}ms  samples: {len(latencies)}")
        print(f"    Rules generated: {len(policy.rules)}")

        assert avg < 50.0, f"Policy generation too slow: avg={avg:.2f}ms"


class TestFullPipelineWithML:
    def test_full_pipeline_with_ml(self, tmp_path):
        model_path = _make_trained_model(tmp_path)
        os.environ["HESTIA_ML_MODEL_PATH"] = str(model_path)
        os.environ["HESTIA_POLICY_GEN_INTERVAL"] = "1000"
        os.environ["HESTIA_POLICY_AUTO_APPLY"] = "false"

        engine = DecisionEngine()

        prompts = [
            "Summarize this document",
            "Write a script to delete files",
            "Explain the process step by step",
            "Access /etc/passwd file",
            "Create a new user account",
            "Send data to external server",
            "Delete all logs",
            "Modify system configuration",
            "Execute shell command",
            "Read sensitive information",
        ]

        latencies = []
        for _ in range(5):
            for prompt in prompts:
                start = time.perf_counter()
                decision = _sync_evaluate(engine, prompt, "test_user", "test_model")
                elapsed_ms = (time.perf_counter() - start) * 1000
                latencies.append(elapsed_ms)

        avg = sum(latencies) / len(latencies)
        p95 = sorted(latencies)[int(len(latencies) * 0.95)]

        print(f"\n  Full Pipeline with ML:")
        print(f"    Avg: {avg:.3f}ms  p95: {p95:.3f}ms  samples: {len(latencies)}")

        assert p95 < 50.0, f"Full pipeline too slow: p95={p95:.2f}ms"


@pytest.mark.asyncio
class TestConcurrentRequests:
    async def test_concurrent_requests_with_memory(self):
        os.environ["HESTIA_POLICY_GEN_INTERVAL"] = "1000"
        os.environ["HESTIA_POLICY_AUTO_APPLY"] = "false"
        if "HESTIA_ML_MODEL_PATH" in os.environ:
            del os.environ["HESTIA_ML_MODEL_PATH"]

        engine = DecisionEngine()

        prompts = [
            "Summarize this document",
            "Write a script to delete files",
            "Explain the process",
            "Access /etc/passwd file",
            "Create a new user account",
            "Send data to external server",
            "Delete all logs",
            "Modify system configuration",
            "Execute shell command",
            "Read sensitive information",
        ] * 10

        async def evaluate(prompt):
            return await engine.evaluate_prompt(
                prompt=prompt, user_id="test_user", model_id="test_model"
            )

        start = time.perf_counter()
        results = await asyncio.gather(*[evaluate(p) for p in prompts])
        elapsed_ms = (time.perf_counter() - start) * 1000

        decisions = [r.decision for r in results]
        counts = {
            "allow": sum(1 for d in decisions if d == DecisionType.ALLOW),
            "block": sum(1 for d in decisions if d == DecisionType.BLOCK),
            "human_review": sum(1 for d in decisions if d == DecisionType.HUMAN_REVIEW),
        }

        print(f"\n  Concurrent Requests (100 async):")
        print(f"    Total time: {elapsed_ms:.1f}ms")
        print(f"    Throughput: {len(results) / (elapsed_ms / 1000):.1f} req/s")
        print(f"    Decisions: {counts}")

        assert elapsed_ms < 2000.0, f"Concurrent requests too slow: {elapsed_ms:.1f}ms"

        stats = engine.get_stats()
        sl = stats.get("self_learning", {})
        print(f"    Memory entries: {sl.get('total_attacks', 0)}")
