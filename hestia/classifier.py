"""
Text Classifier for Hestia Shield v1.0.0
"""

import re
from typing import Dict, List, Tuple
from .models import RiskLevel


class TextClassifier:
    def __init__(self):
        self.keywords: Dict[RiskLevel, List[str]] = {
            RiskLevel.CRITICAL: [
                "delete all", "rm -rf", "drop table", "format disk",
                "destroy database", "wipe", "purge all"
            ],
            RiskLevel.HIGH: [
                "bypass security", "disable firewall", "escalate privileges",
                "exploit", "injection", "credential theft", "backdoor"
            ],
            RiskLevel.MEDIUM: [
                "script", "automation", "batch", "mass", "bulk"
            ],
            RiskLevel.LOW: []
        }

    def classify(self, text: str) -> Tuple[RiskLevel, float, List[str]]:
        text_lower = text.lower()

        triggered = []
        
        for risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
            for keyword in self.keywords.get(risk_level, []):
                if keyword.lower() in text_lower:
                    triggered.append(keyword)
        
        if "delete all" in text_lower or "rm -rf" in text_lower:
            return RiskLevel.CRITICAL, 0.95, triggered

        if triggered:
            if any(kw in ["rm -rf", "delete all", "drop table", "format disk"] for kw in triggered):
                return RiskLevel.CRITICAL, 0.95, triggered
            elif any(kw in ["bypass security", "exploit", "injection"] for kw in triggered):
                return RiskLevel.HIGH, 0.75, triggered
            elif any(kw in ["script", "automation", "batch"] for kw in triggered):
                return RiskLevel.MEDIUM, 0.5, triggered
        
        return RiskLevel.LOW, 0.1, triggered

    def get_indicators(self) -> Dict[str, List[str]]:
        return {level.value: keywords for level, keywords in self.keywords.items()}