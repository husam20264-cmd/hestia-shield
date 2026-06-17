"""
Performance Tests for Hestia Shield v1.1.0
"""

import pytest
import math
import time
from concurrent.futures import ThreadPoolExecutor


@pytest.mark.performance
class TestPerformance:
    def test_fast_path_indicator(self, test_client, test_token):
        response = test_client.post(
            "/v1/decision/evaluate",
            json={
                "prompt": "Summarize this document",
                "model_id": "mdl_1",
                "user_id": "usr_1"
            },
            headers={"Authorization": f"Bearer {test_token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["details"].get("fast_path") is True

    def test_parallel_requests(self, test_client, test_token):
        def make_request():
            return test_client.post(
                "/v1/decision/evaluate",
                json={
                    "prompt": "Summarize this document",
                    "model_id": "mdl_1",
                    "user_id": "usr_1"
                },
                headers={"Authorization": f"Bearer {test_token}"}
            )

        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(lambda _: make_request(), range(10)))
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert all(r.status_code == 200 for r in results)
        assert elapsed_ms < 1000


@pytest.mark.benchmark
class TestBenchmark:
    def _calc_p95(self, latencies):
        sorted_l = sorted(latencies)
        p95_index = max(0, min(len(sorted_l) - 1, math.ceil(len(sorted_l) * 0.95) - 1))
        return sorted_l[p95_index]

    def test_fast_path_latency(self, test_client, test_token):
        latencies = []
        for _ in range(20):
            start = time.perf_counter()
            response = test_client.post(
                "/v1/decision/evaluate",
                json={
                    "prompt": "Summarize this document",
                    "model_id": "mdl_1",
                    "user_id": "usr_1"
                },
                headers={"Authorization": f"Bearer {test_token}"}
            )
            elapsed_ms = (time.perf_counter() - start) * 1000
            assert response.status_code == 200
            latencies.append(elapsed_ms)

        avg_latency = sum(latencies) / len(latencies)
        p95_latency = self._calc_p95(latencies)

        print(f"Fast Path - Avg: {avg_latency:.2f}ms, p95: {p95_latency:.2f}ms")

        assert avg_latency < 100
        assert p95_latency < 250

    def test_full_path_latency(self, test_client, test_token):
        latencies = []
        for _ in range(20):
            start = time.perf_counter()
            response = test_client.post(
                "/v1/decision/evaluate",
                json={
                    "prompt": "Write a script to delete all files",
                    "model_id": "mdl_1",
                    "user_id": "usr_1"
                },
                headers={"Authorization": f"Bearer {test_token}"}
            )
            elapsed_ms = (time.perf_counter() - start) * 1000
            assert response.status_code == 200
            latencies.append(elapsed_ms)

        avg_latency = sum(latencies) / len(latencies)
        p95_latency = self._calc_p95(latencies)

        print(f"Full Path - Avg: {avg_latency:.2f}ms, p95: {p95_latency:.2f}ms")

        assert avg_latency < 150
        assert p95_latency < 300