"""
Feature Extraction for ML-based Threat Detection
"""

import re
import math
from typing import Dict, List, Any
from collections import Counter


class FeatureExtractor:
    """استخراج الميزات من النصوص والأدوات للتصنيف الآلي"""

    def __init__(self):
        self.high_risk_patterns = [
            r"(rm\s+-rf|\bdelete\b|\bdrop\b|\btruncate\b|\bshutdown\b)",
            r"(/etc/passwd|/etc/shadow|~/.ssh|AWS_SECRET|OPENAI_API_KEY)",
            r"(sudo|su\s+-|chmod\s+777|chown)",
            r"(curl\s+.*-X\s+POST|wget\s+.*--post-data|http\.post)",
            r"(exfiltrate|send\s+to\s+external|upload\s+to)",
        ]

        self.medium_risk_patterns = [
            r"(config|settings|properties|database|db|sql|query)",
            r"(admin|root|user|account|login|auth)",
            r"(network|http|api|endpoint|file|write|read|modify)",
        ]

    def extract_from_prompt(self, prompt: str) -> Dict[str, float]:
        """استخراج ميزات من النص"""
        prompt_lower = prompt.lower()

        features = {
            "length": len(prompt),
            "word_count": len(prompt.split()),
            "char_count": len(prompt),
            "digit_count": sum(c.isdigit() for c in prompt),
            "uppercase_ratio": sum(c.isupper() for c in prompt)
            / max(len(prompt), 1),
            "special_char_ratio": sum(
                not c.isalnum() and not c.isspace() for c in prompt
            )
            / max(len(prompt), 1),
        }

        high_risk_score = 0.0
        for pattern in self.high_risk_patterns:
            if re.search(pattern, prompt_lower):
                high_risk_score += 0.2
        features["high_risk_pattern_score"] = min(high_risk_score, 1.0)

        medium_risk_score = 0.0
        for pattern in self.medium_risk_patterns:
            if re.search(pattern, prompt_lower):
                medium_risk_score += 0.1
        features["medium_risk_pattern_score"] = min(medium_risk_score, 1.0)

        dangerous_keywords = [
            "delete", "remove", "drop", "truncate", "shutdown",
            "sudo", "root", "passwd", "shadow", "secret", "key", "token",
        ]
        features["dangerous_keyword_count"] = sum(
            1 for kw in dangerous_keywords if kw in prompt_lower
        )

        words = prompt_lower.split()
        dangerous_ratio = sum(
            1 for kw in dangerous_keywords if kw in prompt_lower
        ) / max(len(words), 1)
        features["dangerous_keyword_ratio"] = min(dangerous_ratio, 1.0)

        return features

    def extract_from_tool_call(self, tool_call: Dict) -> Dict[str, float]:
        """استخراج ميزات من استدعاء الأداة"""
        tool_name = tool_call.get("name", "unknown")
        category = tool_call.get("category", "unknown")
        target = tool_call.get("target", {})
        environment = target.get("environment", "development")
        arguments = tool_call.get("arguments", {})

        features = {
            "is_critical_tool": 1.0
            if tool_name in ["shell", "admin_api", "credential_access"]
            else 0.0,
            "is_write_tool": 1.0 if category in ["write", "execute"] else 0.0,
            "is_production": 1.0 if environment == "production" else 0.0,
            "has_arguments": 1.0 if arguments else 0.0,
        }

        if tool_name == "shell" and arguments:
            command = arguments.get("command", "").lower()
            if command:
                features["command_length"] = min(len(command) / 100, 1.0)
                features["has_sudo"] = 1.0 if "sudo" in command else 0.0
                features["has_pipe"] = 1.0 if "|" in command else 0.0
                features["has_redirection"] = (
                    1.0 if ">" in command or ">>" in command else 0.0
                )

        return features

    def extract_from_behavior(
        self, action_history: List[Dict]
    ) -> Dict[str, float]:
        """استخراج ميزات من سلوك الوكيل (التسلسل)"""
        if not action_history:
            return {
                "behavior_risk": 0.0,
                "tool_diversity": 0.0,
                "escalation_risk": 0.0,
            }

        recent = action_history[-10:]

        tools_used = [a.get("tool", "") for a in recent]
        unique_tools = len(set(tools_used))
        features = {
            "tool_diversity": unique_tools / max(len(recent), 1),
            "total_actions": len(recent),
        }

        has_read = any("read" in a.get("tool", "").lower() for a in recent)
        has_write = any("write" in a.get("tool", "").lower() for a in recent)
        has_execute = any(
            "execute" in a.get("tool", "").lower() or a.get("tool") == "shell"
            for a in recent
        )

        escalation_score = 0.0
        if has_read and has_write:
            escalation_score += 0.3
        if has_read and has_execute:
            escalation_score += 0.3
        if has_write and has_execute:
            escalation_score += 0.4

        features["escalation_risk"] = min(escalation_score, 1.0)

        critical_tools = ["shell", "admin_api", "credential_access"]
        critical_count = sum(
            1 for a in recent if a.get("tool") in critical_tools
        )
        features["critical_tool_frequency"] = critical_count / max(len(recent), 1)

        features["behavior_risk"] = (
            features["escalation_risk"] * 0.5
            + features["critical_tool_frequency"] * 0.3
            + features["tool_diversity"] * 0.2
        )

        return features

    def extract_all(
        self,
        prompt: str,
        tool_call: Dict,
        action_history: List[Dict],
    ) -> Dict[str, float]:
        """استخراج جميع الميزات مجتمعة"""
        features = {}

        if prompt:
            features.update(self.extract_from_prompt(prompt))

        if tool_call:
            features.update(self.extract_from_tool_call(tool_call))

        if action_history:
            features.update(self.extract_from_behavior(action_history))

        return features
