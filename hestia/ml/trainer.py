"""
Training Pipeline for ML-based Threat Detection
"""

import json
import numpy as np
from typing import List, Dict, Tuple
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

from .model import ThreatDetectionModel
from .feature_extractor import FeatureExtractor


class ModelTrainer:
    """تدريب نموذج الكشف عن التهديدات"""

    def __init__(self):
        self.feature_extractor = FeatureExtractor()

    def prepare_dataset(
        self, data_path: Path
    ) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        تجهيز البيانات للتدريب
        البيانات المتوقعة: مصفوفة من {'prompt': ..., 'tool_call': ..., 'label': 0/1}
        """
        with open(data_path, "r") as f:
            samples = json.load(f)

        features_list = []
        labels = []

        for sample in samples:
            features = self.feature_extractor.extract_all(
                prompt=sample.get("prompt", ""),
                tool_call=sample.get("tool_call", {}),
                action_history=sample.get("action_history", []),
            )
            features_list.append(features)
            labels.append(sample.get("label", 0))

        if not features_list:
            return np.array([]), np.array([]), []

        feature_names = sorted(features_list[0].keys())
        X = np.zeros((len(features_list), len(feature_names)))

        for i, feats in enumerate(features_list):
            for j, name in enumerate(feature_names):
                X[i, j] = feats.get(name, 0.0)

        y = np.array(labels)

        return X, y, feature_names

    def train(
        self, X: np.ndarray, y: np.ndarray, test_size: float = 0.2
    ) -> Dict:
        """تدريب النموذج وتقييمه"""
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )

        model = ThreatDetectionModel()
        model.initialize(n_estimators=50, max_depth=10)
        model.fit(X_train, y_train)

        y_pred = model.model.predict(model.scaler.transform(X_test))
        y_proba = model.model.predict_proba(model.scaler.transform(X_test))[
            :, 1
        ]

        return {
            "model": model,
            "metrics": {
                "classification_report": classification_report(
                    y_test, y_pred, output_dict=True
                ),
                "roc_auc": roc_auc_score(y_test, y_proba),
                "accuracy": float((y_pred == y_test).sum() / len(y_test)),
                "feature_names": model.feature_names,
            },
        }

    def train_from_file(
        self, data_path: Path, output_path: Path
    ) -> Dict:
        """تدريب النموذج من ملف البيانات"""
        X, y, feature_names = self.prepare_dataset(data_path)

        if X.size == 0:
            raise ValueError("No data found in the dataset")

        result = self.train(X, y)

        result["model"].feature_names = feature_names
        result["model"].save(output_path)

        return result["metrics"]
