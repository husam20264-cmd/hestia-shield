"""
Inference Engine for ML-based Threat Detection
"""

from typing import Dict, Optional, Tuple
from pathlib import Path

from .model import ThreatDetectionModel
from .feature_extractor import FeatureExtractor


class ThreatInference:
    """
    محرك تنفيذ نموذج الكشف عن التهديدات
    """

    def __init__(self, model_path: Optional[Path] = None):
        self.model = None
        self.feature_extractor = FeatureExtractor()

        if model_path and model_path.exists():
            self.load_model(model_path)

    def load_model(self, model_path: Path):
        """تحميل النموذج"""
        self.model = ThreatDetectionModel(model_path)
        self.model.load(model_path)

    def evaluate(
        self,
        prompt: str = "",
        tool_call: Dict = None,
        action_history: list = None,
    ) -> Tuple[float, bool]:
        """
        تقييم مدخل باستخدام النموذج
        Returns: (risk_score, is_threat)
        """
        if self.model is None:
            return 0.0, False

        features = self.feature_extractor.extract_all(
            prompt=prompt or "",
            tool_call=tool_call or {},
            action_history=action_history or [],
        )

        return self.model.predict(features)

    def get_risk_score(
        self,
        prompt: str = "",
        tool_call: Dict = None,
        action_history: list = None,
    ) -> float:
        """الحصول على درجة الخطر فقط"""
        risk_score, _ = self.evaluate(prompt, tool_call, action_history)
        return risk_score

    def get_feature_importance(self) -> Dict[str, float]:
        """الحصول على أهمية الميزات (إذا كان النموذج مدعوماً)"""
        if self.model is None or self.model.model is None:
            return {}

        if hasattr(self.model.model, "feature_importances_"):
            importance = self.model.model.feature_importances_
            features = self.model.feature_names

            return dict(
                sorted(
                    zip(features, importance),
                    key=lambda x: x[1],
                    reverse=True,
                )[:10]
            )

        return {}
