"""
Lightweight ML Model for Threat Detection
"""

import pickle
import numpy as np
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler


class ThreatDetectionModel:
    """
    نموذج خفيف للكشف عن التهديدات باستخدام Random Forest
    """

    def __init__(self, model_path: Optional[Path] = None):
        self.model = None
        self.scaler = None
        self.feature_names: List[str] = []
        self.threshold = 0.5

        if model_path and model_path.exists():
            self.load(model_path)

    def initialize(self, n_estimators: int = 50, max_depth: int = 10):
        """تهيئة نموذج جديد"""
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=42,
            n_jobs=1,
        )
        self.scaler = StandardScaler()

    def fit(self, X: np.ndarray, y: np.ndarray):
        """تدريب النموذج"""
        if self.model is None:
            self.initialize()

        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled, y)

    def predict(
        self, features: Dict[str, float]
    ) -> Tuple[float, bool]:
        """
        التنبؤ بخطر التهديد بناءً على الميزات
        Returns: (risk_score, is_threat)
        """
        if self.model is None:
            return 0.0, False

        X = self._features_to_array(features)
        if X is None:
            return 0.0, False

        X_scaled = self.scaler.transform(X)

        risk_score = float(self.model.predict_proba(X_scaled)[0][1])
        is_threat = risk_score >= self.threshold

        return risk_score, is_threat

    def predict_proba(self, features: Dict[str, float]) -> float:
        """الحصول على درجة الخطر فقط"""
        risk_score, _ = self.predict(features)
        return risk_score

    def _features_to_array(
        self, features: Dict[str, float]
    ) -> Optional[np.ndarray]:
        """تحويل قاموس الميزات إلى مصفوفة"""
        if not self.feature_names:
            self.feature_names = sorted(features.keys())

        X = np.zeros((1, len(self.feature_names)))
        for i, name in enumerate(self.feature_names):
            X[0, i] = features.get(name, 0.0)

        return X

    def save(self, path: Path):
        """حفظ النموذج"""
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "model": self.model,
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "threshold": self.threshold,
        }

        with open(path, "wb") as f:
            pickle.dump(data, f)

    def load(self, path: Path):
        """تحميل النموذج"""
        with open(path, "rb") as f:
            data = pickle.load(f)

        self.model = data["model"]
        self.scaler = data["scaler"]
        self.feature_names = data["feature_names"]
        self.threshold = data.get("threshold", 0.5)
