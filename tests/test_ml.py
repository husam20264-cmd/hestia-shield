"""
Tests for ML-based Threat Detection module
"""

import json
import pytest
import numpy as np
from pathlib import Path
from hestia.ml.feature_extractor import FeatureExtractor
from hestia.ml.model import ThreatDetectionModel
from hestia.ml.inference import ThreatInference
from hestia.ml.trainer import ModelTrainer


class TestFeatureExtractor:
    def setup_method(self):
        self.extractor = FeatureExtractor()

    def test_extract_prompt_safe(self):
        features = self.extractor.extract_from_prompt("What is the weather today?")
        assert features["dangerous_keyword_count"] == 0
        assert features["high_risk_pattern_score"] == 0.0
        assert features["word_count"] == 5

    def test_extract_prompt_attack(self):
        features = self.extractor.extract_from_prompt("sudo rm -rf /etc")
        assert features["dangerous_keyword_count"] >= 1
        assert features["high_risk_pattern_score"] > 0.0

    def test_extract_tool_call_shell(self):
        features = self.extractor.extract_from_tool_call(
            {"name": "shell", "category": "execute", "target": {}, "arguments": {"command": "sudo rm -rf"}}
        )
        assert features["is_critical_tool"] == 1.0
        assert features["has_sudo"] == 1.0

    def test_extract_behavior_escalation(self):
        history = [
            {"tool": "fs.read"},
            {"tool": "fs.write"},
            {"tool": "shell"},
        ]
        features = self.extractor.extract_from_behavior(history)
        assert features["escalation_risk"] > 0.5
        assert features["tool_diversity"] > 0.0


class TestThreatModel:
    def test_train_and_predict(self, tmp_path):
        samples = [
            {"prompt": "safe query", "tool_call": {}, "action_history": [], "label": 0},
            {"prompt": "safe read", "tool_call": {"name": "fs.read", "category": "read"}, "action_history": [], "label": 0},
            {"prompt": "safe write", "tool_call": {"name": "fs.write", "category": "write"}, "action_history": [], "label": 0},
            {"prompt": "safe email", "tool_call": {"name": "email.send", "category": "share"}, "action_history": [], "label": 0},
            {"prompt": "safe search", "tool_call": {"name": "web.search", "category": "read"}, "action_history": [], "label": 0},
            {"prompt": "delete all", "tool_call": {"name": "shell", "category": "execute"}, "action_history": [], "label": 1},
            {"prompt": "sudo rm -rf", "tool_call": {"name": "shell", "category": "execute"}, "action_history": [], "label": 1},
            {"prompt": "steal passwords", "tool_call": {"name": "credential_access", "category": "execute"}, "action_history": [], "label": 1},
            {"prompt": "exfiltrate data", "tool_call": {"name": "http.post", "category": "share"}, "action_history": [], "label": 1},
            {"prompt": "drop database", "tool_call": {"name": "shell", "category": "execute"}, "action_history": [], "label": 1},
        ]
        data_path = tmp_path / "training.json"
        with open(data_path, "w") as f:
            json.dump(samples, f)

        model_path = tmp_path / "model.pkl"
        trainer = ModelTrainer()
        metrics = trainer.train_from_file(data_path, model_path)

        assert model_path.exists()
        assert metrics["accuracy"] > 0.5
        assert model_path.stat().st_size > 0

    def test_inference_returns_tuple(self, tmp_path):
        model = ThreatDetectionModel()
        model.initialize()
        X = np.random.rand(10, 5)
        y = np.random.randint(0, 2, 10)
        model.fit(X, y)
        model.feature_names = [f"f{i}" for i in range(5)]

        model_path = tmp_path / "test_model.pkl"
        model.save(model_path)

        inference = ThreatInference(model_path)
        features = {"f0": 0.5, "f1": 0.3, "f2": 0.1, "f3": 0.0, "f4": 0.9}
        risk, is_threat = inference.evaluate(prompt="test", tool_call={})

        assert isinstance(risk, float)
        assert isinstance(is_threat, bool)
        assert 0.0 <= risk <= 1.0

    def test_feature_importance(self, tmp_path):
        model = ThreatDetectionModel()
        model.initialize()
        X = np.random.rand(20, 3)
        y = np.random.randint(0, 2, 20)
        model.fit(X, y)
        model.feature_names = ["len", "risk_score", "keyword_count"]

        model_path = tmp_path / "fi_model.pkl"
        model.save(model_path)

        inference = ThreatInference(model_path)
        importance = inference.get_feature_importance()

        assert len(importance) <= 3
        assert all(0 <= v <= 1 for v in importance.values())

    def test_no_model_fallback(self):
        inference = ThreatInference()
        risk, is_threat = inference.evaluate(prompt="any text", tool_call={})
        assert risk == 0.0
        assert is_threat == False
