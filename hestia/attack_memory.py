"""
Attack Memory for Hestia Shield v1.0.0
"""

import hashlib
import time
from typing import Dict, List, Optional
from collections import defaultdict
from datetime import datetime, timedelta
from .models import RiskLevel, DecisionType


class AttackMemory:
    def __init__(self, window_seconds: int = 3600, max_entries: int = 10000):
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        self.user_history: Dict[str, List[Dict]] = defaultdict(list)
        self.pattern_cache: Dict[str, Dict] = {}

    def record_event(self, user_id: str, event_data: Dict):
        event = {
            "timestamp": time.time(),
            "data": event_data
        }

        history = self.user_history[user_id]
        history.append(event)

        if len(history) > self.max_entries:
            history.pop(0)

    def get_user_risk_profile(self, user_id: str) -> Dict:
        now = time.time()
        cutoff = now - self.window_seconds

        history = self.user_history.get(user_id, [])
        recent_events = [e for e in history if e["timestamp"] > cutoff]

        if not recent_events:
            return {
                "risk_score": 0.0,
                "total_events": 0,
                "blocked_events": 0,
                "attack_patterns": []
            }

        blocked_count = sum(
            1 for e in recent_events
            if e["data"].get("decision", {}).get("decision") in ["block", "terminate_session"]
        )

        total_events = len(recent_events)
        block_ratio = blocked_count / total_events if total_events > 0 else 0

        risk_score = min(1.0, block_ratio * 1.5)

        return {
            "risk_score": risk_score,
            "total_events": total_events,
            "blocked_events": blocked_count,
            "attack_patterns": self._detect_patterns(user_id, recent_events)
        }

    def _detect_patterns(self, user_id: str, events: List[Dict]) -> List[str]:
        patterns = []

        timestamps = [e["timestamp"] for e in events]
        if len(timestamps) >= 5:
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            avg_interval = sum(intervals) / len(intervals) if intervals else 0
            if avg_interval < 2:
                patterns.append("rapid_fire_requests")

        tool_calls = [
            e["data"].get("tool_call", {})
            for e in events
            if e["data"].get("tool_call")
        ]
        unique_tools = set(tc.get("name") for tc in tool_calls)
        if len(unique_tools) > 10:
            patterns.append("tool_enumeration")

        return patterns

    def should_rate_limit(self, user_id: str, max_per_minute: int = 60) -> bool:
        now = time.time()
        one_minute_ago = now - 60

        history = self.user_history.get(user_id, [])
        recent = [e for e in history if e["timestamp"] > one_minute_ago]

        return len(recent) > max_per_minute

    def clear_user(self, user_id: str):
        if user_id in self.user_history:
            del self.user_history[user_id]

    def get_stats(self) -> Dict:
        total_users = len(self.user_history)
        total_events = sum(len(h) for h in self.user_history.values())

        return {
            "total_users": total_users,
            "total_events": total_events,
            "window_seconds": self.window_seconds,
            "max_entries_per_user": self.max_entries
        }