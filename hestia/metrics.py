"""
Metrics Collector for Hestia Shield v1.0.0
"""

import time
from typing import Dict, List, Optional
from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class Metric:
    name: str
    value: float
    timestamp: float = field(default_factory=time.time)
    labels: Dict[str, str] = field(default_factory=dict)


class MetricsCollector:
    def __init__(self, max_samples: int = 10000):
        self.metrics: List[Metric] = []
        self.histories: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_samples))
        self.counters: Dict[str, int] = defaultdict(int)
        self.gauges: Dict[str, float] = {}
        self.percentiles: Dict[str, List[float]] = defaultdict(list)

    def record(self, name: str, value: float, labels: Optional[Dict] = None):
        metric = Metric(name=name, value=value, labels=labels or {})
        self.metrics.append(metric)
        self.histories[name].append(value)

        if "latency" in name:
            self.percentiles[name].append(value)
            if len(self.percentiles[name]) > 1000:
                self.percentiles[name] = self.percentiles[name][-1000:]

    def increment(self, name: str, amount: int = 1, labels: Optional[Dict] = None):
        key = f"{name}{labels or {}}"
        self.counters[key] += amount

    def gauge(self, name: str, value: float):
        self.gauges[name] = value

    def get_percentile(self, name: str, percentile: float) -> Optional[float]:
        values = self.percentiles.get(name, [])
        if not values:
            return None

        sorted_values = sorted(values)
        index = int(len(sorted_values) * percentile / 100)
        return sorted_values[min(index, len(sorted_values) - 1)]

    def get_summary(self) -> Dict:
        return {
            "counters": dict(self.counters),
            "gauges": dict(self.gauges),
            "percentiles": {
                name: {
                    "p50": self.get_percentile(name, 50),
                    "p95": self.get_percentile(name, 95),
                    "p99": self.get_percentile(name, 99),
                }
                for name in self.percentiles
            },
            "total_metrics": len(self.metrics)
        }