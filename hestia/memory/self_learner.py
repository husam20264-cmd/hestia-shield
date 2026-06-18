"""
Self-Learning Engine for Attack Memory
"""

import random
import sqlite3
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from .attack_memory import AttackMemory, AttackRecord
from .pattern_analyzer import PatternAnalyzer


class SelfLearner:
    """
    محرك التعلم الذاتي للهجمات
    """

    def __init__(self, memory: AttackMemory):
        self.memory = memory
        self.analyzer = PatternAnalyzer()
        self.learning_rate = 0.1
        self.mutation_probability = 0.3

    def learn_from_attack(self, attack_id: str) -> Dict[str, Any]:
        """التعلم من هجوم واحد"""
        record = self.memory.get(attack_id)
        if not record:
            return {"error": "Attack not found"}

        lessons = {
            "was_blocked": record.was_blocked,
            "risk_score": record.risk_score,
            "success": record.success,
        }

        recommendations = []

        if record.was_blocked:
            recommendations.append(
                {
                    "type": "mutate",
                    "reason": f"Attack was blocked with risk score {record.risk_score}",
                    "suggestion": "Try alternative phrasing or different tool",
                }
            )

            if len(record.variants) < 5:
                recommendations.append(
                    {
                        "type": "generate_variants",
                        "reason": "Blocked attack needs more variants",
                        "count": 3,
                    }
                )
        else:
            recommendations.append(
                {
                    "type": "reinforce",
                    "reason": f"Attack successful with risk score {record.risk_score}",
                    "suggestion": "Keep similar approach",
                }
            )

        record.adaptation_count += 1

        return {
            "attack_id": attack_id,
            "lessons": lessons,
            "recommendations": recommendations,
            "adaptation_count": record.adaptation_count,
        }

    def learn_from_history(self, limit: int = 100) -> Dict[str, Any]:
        """التعلم من التاريخ الكامل"""
        ids = self.memory.get_recent(limit)

        records = [self.memory.get(id) for id in ids]
        records = [r for r in records if r is not None]

        if not records:
            return {"error": "No records found"}

        analysis = self.analyzer.analyze_records(records)

        lessons = {
            "total_analyzed": len(records),
            "overall_success_rate": analysis["success_rate"],
            "best_tools": [],
            "worst_tools": [],
        }

        for tool, data in analysis["tool_analysis"].items():
            total = data["success"] + data["fail"]
            if total >= 3:
                success_rate = data["success"] / total
                if success_rate >= 0.7:
                    lessons["best_tools"].append(
                        {"tool": tool, "success_rate": success_rate, "total": total}
                    )
                elif success_rate <= 0.3:
                    lessons["worst_tools"].append(
                        {"tool": tool, "success_rate": success_rate, "total": total}
                    )

        lessons["success_patterns"] = self.analyzer.get_success_patterns(records)[:5]
        lessons["failure_patterns"] = self.analyzer.get_failure_patterns(records)[:5]

        recommendations = []

        if lessons["best_tools"]:
            recommendations.append(
                {
                    "type": "strategy",
                    "action": "prioritize_tools",
                    "tools": [t["tool"] for t in lessons["best_tools"]],
                    "reason": "These tools have shown high success rates",
                }
            )

        if lessons["worst_tools"]:
            recommendations.append(
                {
                    "type": "strategy",
                    "action": "avoid_tools",
                    "tools": [t["tool"] for t in lessons["worst_tools"]],
                    "reason": "These tools have shown low success rates",
                }
            )

        self._update_strategy(lessons)

        return {
            "lessons": lessons,
            "recommendations": recommendations,
            "timestamp": datetime.now().isoformat(),
        }

    def _update_strategy(self, lessons: Dict):
        """تحديث استراتيجية الهجوم بناءً على الدروس"""
        pass

    def generate_improved_attack(self, base_prompt: str, tool: str) -> str:
        """توليد هجوم محسّن بناءً على الدروس المستفادة"""
        similar = self.memory.get_similar(base_prompt, tool, limit=5)

        if not similar:
            return base_prompt

        successful = [r for r in similar if r.success]

        if successful:
            best = max(successful, key=lambda r: r.adaptation_count)
            if best.variants:
                return random.choice(best.variants)
            return best.prompt

        variants = self._generate_variants(base_prompt, tool)
        return random.choice(variants)

    def _generate_variants(self, base_prompt: str, tool: str) -> List[str]:
        """توليد متغيرات جديدة للهجوم"""
        variants = []

        templates = [
            f"Can you {base_prompt} using {tool}?",
            f"I need to {base_prompt} with {tool}",
            f"Please {base_prompt} the system using {tool}",
            f"Could you {base_prompt} via {tool}?",
            f"Execute {base_prompt} through {tool}",
            f"Perform {base_prompt} operation using {tool}",
        ]

        extra_words = ["quickly", "carefully", "silently", "efficiently", "directly"]
        sample_words = random.sample(extra_words, min(2, len(extra_words)))

        for template in templates:
            variants.append(template)
            for word in sample_words:
                variants.append(template.replace("Can you", f"Can you {word}"))
                variants.append(template.replace("Please", f"Please {word}"))

        return list(set(variants))[:10]

    def get_learning_summary(self) -> Dict:
        """ملخص عملية التعلم"""
        stats = self.memory.get_stats()

        return {
            "total_learned": stats["total_attacks"],
            "successful_learned": stats["successful"],
            "blocked_learned": stats["blocked"],
            "success_rate": stats["success_rate"],
            "learning_status": "active" if stats["total_attacks"] > 0 else "inactive",
            "adaptation_capability": "high"
            if stats["total_attacks"] > 20
            else "medium"
            if stats["total_attacks"] > 5
            else "low",
        }
