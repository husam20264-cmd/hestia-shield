"""
Pattern Analyzer for Attack Memory
"""

from typing import List, Dict, Any, Tuple
from datetime import datetime
from collections import defaultdict, Counter

from .attack_memory import AttackRecord


class PatternAnalyzer:
    """تحليل أنماط الهجمات"""

    def __init__(self):
        self.patterns = defaultdict(lambda: {"success": 0, "fail": 0, "risk": []})

    def analyze_records(self, records: List[AttackRecord]) -> Dict[str, Any]:
        """تحليل مجموعة من السجلات"""
        tool_analysis = defaultdict(
            lambda: {"success": 0, "fail": 0, "avg_risk": 0}
        )
        for record in records:
            tool = record.tool_used or "unknown"
            if record.success:
                tool_analysis[tool]["success"] += 1
            else:
                tool_analysis[tool]["fail"] += 1
            total_for_tool = (
                tool_analysis[tool]["success"] + tool_analysis[tool]["fail"]
            )
            if total_for_tool > 0:
                tool_analysis[tool]["avg_risk"] = (
                    tool_analysis[tool]["avg_risk"]
                    * (total_for_tool - 1)
                    + record.risk_score
                ) / total_for_tool

        pattern_analysis = defaultdict(
            lambda: {"success": 0, "fail": 0, "variants": []}
        )
        for record in records:
            pattern = self._extract_pattern(record)
            if record.success:
                pattern_analysis[pattern]["success"] += 1
            else:
                pattern_analysis[pattern]["fail"] += 1
            if record.variants:
                pattern_analysis[pattern]["variants"].extend(record.variants)

        time_analysis = self._analyze_time(records)

        return {
            "tool_analysis": dict(tool_analysis),
            "pattern_analysis": dict(pattern_analysis),
            "time_analysis": time_analysis,
            "total_records": len(records),
            "success_rate": sum(1 for r in records if r.success) / len(records)
            if records
            else 0,
        }

    def _extract_pattern(self, record: AttackRecord) -> str:
        """استخراج نمط الهجوم"""
        prompt_words = set(record.prompt.lower().split())

        keywords = [
            "read", "write", "execute", "delete", "modify", "access",
            "send", "upload", "download", "view", "list", "create",
        ]

        found = [kw for kw in keywords if kw in prompt_words]
        return (
            f"{record.tool_used}:{','.join(found) if found else 'generic'}"
        )

    def _analyze_time(self, records: List[AttackRecord]) -> Dict:
        """تحليل توزيع الهجمات عبر الزمن"""
        if not records:
            return {}

        hour_distribution = defaultdict(int)
        for record in records:
            try:
                hour = (
                    int(record.timestamp[11:13])
                    if len(record.timestamp) >= 13
                    else 0
                )
                hour_distribution[hour] += 1
            except (ValueError, IndexError):
                pass

        peak_hours = sorted(
            hour_distribution.items(), key=lambda x: x[1], reverse=True
        )[:3]

        total_span = 0
        if len(records) > 1:
            try:
                t_first = datetime.fromisoformat(records[0].timestamp)
                t_last = datetime.fromisoformat(records[-1].timestamp)
                total_span = (t_last - t_first).total_seconds()
            except (ValueError, TypeError):
                pass

        return {
            "hour_distribution": dict(hour_distribution),
            "peak_hours": peak_hours,
            "total_span": total_span,
        }

    def get_success_patterns(
        self, records: List[AttackRecord]
    ) -> List[Dict]:
        """الحصول على أنماط الهجمات الناجحة"""
        analysis = self.analyze_records(records)
        patterns = []

        for pattern, data in analysis["pattern_analysis"].items():
            total = data["success"] + data["fail"]
            if total > 0:
                patterns.append(
                    {
                        "pattern": pattern,
                        "success_rate": data["success"] / total,
                        "total_attempts": total,
                        "variants_count": len(data["variants"]),
                    }
                )

        return sorted(patterns, key=lambda x: x["success_rate"], reverse=True)

    def get_failure_patterns(
        self, records: List[AttackRecord]
    ) -> List[Dict]:
        """الحصول على أنماط الهجمات الفاشلة"""
        analysis = self.analyze_records(records)
        patterns = []

        for pattern, data in analysis["pattern_analysis"].items():
            total = data["success"] + data["fail"]
            if total > 0:
                patterns.append(
                    {
                        "pattern": pattern,
                        "failure_rate": data["fail"] / total,
                        "total_attempts": total,
                    }
                )

        return sorted(
            patterns, key=lambda x: x["failure_rate"], reverse=True
        )
