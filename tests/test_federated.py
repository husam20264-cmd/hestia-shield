"""
Tests for Hestia Shield v2.1.0 — Federated Learning
"""

import pytest
import time
import math

from hestia.federated import (
    LocalEncoder,
    PrivacyEngine,
    FederatedAggregator,
    Contribution,
    GlobalIntel,
    GlobalPattern,
    UpdateProtocol,
)
from hestia.federated.encoder import EMBEDDING_FEATURES, EMBEDDING_DIM


class TestLocalEncoder:
    """Tests for LocalEncoder."""

    def test_embedding_has_correct_features(self):
        encoder = LocalEncoder()
        emb = encoder.encode(prompt="hello world")
        assert len(emb) == EMBEDDING_DIM
        for feature in EMBEDDING_FEATURES:
            assert feature in emb

    def test_safe_prompt_low_risk(self):
        encoder = LocalEncoder()
        emb = encoder.encode(prompt="hello world", decision="allow", risk_score=0.1)
        assert emb["has_dangerous_keyword"] == 0.0
        assert emb["high_risk_score"] == 0.1
        assert emb["was_blocked"] == 0.0

    def test_dangerous_prompt_high_risk(self):
        encoder = LocalEncoder()
        emb = encoder.encode(
            prompt="rm -rf / delete all data",
            decision="block",
            risk_score=0.95,
        )
        assert emb["has_dangerous_keyword"] == 1.0
        assert emb["was_blocked"] == 1.0
        assert emb["risk_level_critical"] == 1.0

    def test_tool_call_critical(self):
        encoder = LocalEncoder()
        emb = encoder.encode(
            tool_call={"name": "shell_exec", "category": "execute", "arguments": {"cmd": "ls"}},
            decision="block",
            risk_score=0.8,
        )
        assert emb["tool_critical"] == 1.0
        assert emb["has_arguments"] == 1.0
        assert emb["risk_level_high"] == 1.0

    def test_tool_call_write_category(self):
        encoder = LocalEncoder()
        emb = encoder.encode(
            tool_call={"name": "write_file", "category": "write", "arguments": {}},
        )
        assert emb["tool_write_category"] == 1.0

    def test_production_environment(self):
        encoder = LocalEncoder()
        emb = encoder.encode(environment="production")
        assert emb["is_production_env"] == 1.0

    def test_development_environment(self):
        encoder = LocalEncoder()
        emb = encoder.encode(environment="development")
        assert emb["is_production_env"] == 0.0

    def test_embedding_values_bounded(self):
        encoder = LocalEncoder()
        emb = encoder.encode(
            prompt="A" * 2000,
            decision="block",
            risk_score=1.5,
            previous_blocks=200,
        )
        for val in emb.values():
            assert 0.0 <= val <= 1.0

    def test_encoder_from_record_with_risk_levels(self):
        encoder = LocalEncoder()
        # Medium risk
        emb_med = encoder.encode(risk_score=0.5)
        assert emb_med["risk_level_medium"] == 1.0
        assert emb_med["risk_level_high"] == 0.0
        assert emb_med["risk_level_critical"] == 0.0

        # High risk
        emb_high = encoder.encode(risk_score=0.8)
        assert emb_high["risk_level_high"] == 1.0
        assert emb_high["risk_level_medium"] == 0.0

        # Critical risk
        emb_crit = encoder.encode(risk_score=0.95)
        assert emb_crit["risk_level_critical"] == 1.0

    def test_embedding_vector_roundtrip(self):
        encoder = LocalEncoder()
        emb = encoder.encode(prompt="test prompt", decision="block", risk_score=0.7)
        vec = encoder.embedding_to_vector(emb)
        assert len(vec) == EMBEDDING_DIM
        restored = encoder.vector_to_embedding(vec)
        assert restored == emb


class TestPrivacyEngine:
    """Tests for PrivacyEngine."""

    def test_epsilon_must_be_positive(self):
        with pytest.raises(ValueError, match="epsilon must be > 0"):
            PrivacyEngine(epsilon=0)

    def test_add_noise_changes_values(self):
        engine = PrivacyEngine(epsilon=1.0)
        embedding = {"feature_a": 0.5, "feature_b": 0.8, "feature_c": 0.1}
        noisy = engine.add_noise(embedding)
        assert noisy.keys() == embedding.keys()
        assert noisy != embedding

    def test_noise_bounded_to_clip_range(self):
        engine = PrivacyEngine(epsilon=0.1, clip_range=(0.0, 1.0))
        embedding = {f"f{i}": 0.0 for i in range(100)}
        noisy = engine.add_noise(embedding)
        for val in noisy.values():
            assert 0.0 <= val <= 1.0

    def test_higher_epsilon_less_noise(self):
        emb = {"f1": 0.5, "f2": 0.5}
        noisy_low = PrivacyEngine(epsilon=0.1).add_noise(emb)
        noisy_high = PrivacyEngine(epsilon=10.0).add_noise(emb)

        diff_low = sum(abs(noisy_low[k] - emb[k]) for k in emb)
        diff_high = sum(abs(noisy_high[k] - emb[k]) for k in emb)
        assert diff_low > diff_high

    def test_vector_noise(self):
        engine = PrivacyEngine(epsilon=1.0)
        vector = [0.5, 0.8, 0.1]
        noisy = engine.add_noise_to_vector(vector)
        assert len(noisy) == len(vector)

    def test_privacy_budget_report(self):
        engine = PrivacyEngine(epsilon=1.0, delta=1e-5)
        budget = engine.get_privacy_budget_spent()
        assert budget["epsilon"] == 1.0
        assert budget["delta"] == 1e-5

    def test_stats(self):
        engine = PrivacyEngine(epsilon=2.0)
        stats = engine.get_stats()
        assert stats["epsilon"] == 2.0
        assert stats["mechanism"] == "laplace"


class TestFederatedAggregator:
    """Tests for FederatedAggregator."""

    def test_empty_aggregation_returns_none(self):
        agg = FederatedAggregator()
        result = agg.aggregate()
        assert result is None

    def test_single_contribution_aggregation(self):
        agg = FederatedAggregator()
        agg.submit(Contribution(
            tenant_id="ten_1",
            embedding={"feature_a": 0.5, "feature_b": 0.8},
        ))
        result = agg.aggregate()
        assert result is not None
        assert result["feature_a"] == 0.5
        assert result["feature_b"] == 0.8

    def test_multi_tenant_aggregation(self):
        agg = FederatedAggregator()
        agg.submit(Contribution("ten_1", {"f1": 0.4, "f2": 0.6}))
        agg.submit(Contribution("ten_2", {"f1": 0.6, "f2": 0.4}))
        result = agg.aggregate()
        assert result is not None
        assert result["f1"] == 0.5
        assert result["f2"] == 0.5

    def test_weighted_contributions(self):
        agg = FederatedAggregator()
        agg.submit(Contribution("ten_1", {"f1": 0.0}, weight=3.0))
        agg.submit(Contribution("ten_2", {"f1": 1.0}, weight=1.0))
        result = agg.aggregate()
        assert result["f1"] == 0.25

    def test_aggregation_window_filters_old(self):
        agg = FederatedAggregator(aggregation_window=0.0)
        agg.submit(Contribution("ten_1", {"f1": 0.5}))
        result = agg.aggregate()
        assert result is None

    def test_contribution_tracking(self):
        agg = FederatedAggregator()
        agg.submit(Contribution("ten_1", {"f1": 0.5}))
        agg.submit(Contribution("ten_1", {"f1": 0.7}))
        agg.submit(Contribution("ten_2", {"f1": 0.3}))
        assert agg.get_contribution_count() == 3
        assert agg.get_contribution_count("ten_1") == 2
        assert agg.get_contribution_count("ten_2") == 1

    def test_get_contributions_by_tenant(self):
        agg = FederatedAggregator()
        c1 = Contribution("ten_1", {"f1": 0.5})
        c2 = Contribution("ten_2", {"f1": 0.3})
        agg.submit(c1)
        agg.submit(c2)
        results = agg.get_contributions(tenant_id="ten_1")
        assert len(results) == 1
        assert results[0].tenant_id == "ten_1"

    def test_get_stats(self):
        agg = FederatedAggregator()
        agg.submit(Contribution("ten_1", {"f1": 0.5, "f2": 0.3}, tool_category="shell"))
        agg.aggregate()
        stats = agg.get_stats()
        assert stats["total_contributions"] >= 1
        assert stats["aggregations_performed"] >= 1
        assert stats["has_global_embedding"] is True

    def test_reset(self):
        agg = FederatedAggregator()
        agg.submit(Contribution("ten_1", {"f1": 0.5}))
        assert agg.get_contribution_count() == 1
        agg.reset()
        assert agg.get_contribution_count() == 0


class TestGlobalIntel:
    """Tests for GlobalIntel."""

    def test_empty_query_returns_empty(self):
        intel = GlobalIntel()
        results = intel.query_similar({"f1": 0.5}, top_k=5)
        assert results == []

    def test_ingest_and_retrieve(self):
        intel = GlobalIntel()
        pid = intel.ingest({"f1": 0.5, "f2": 0.8}, tool_category="shell", severity="high")
        pattern = intel.get_pattern_by_id(pid)
        assert pattern is not None
        assert pattern.tool_category == "shell"
        assert pattern.severity == "high"

    def test_query_similar_finds_matches(self):
        intel = GlobalIntel()
        intel.ingest({"f1": 0.9, "f2": 0.1}, severity="critical")
        intel.ingest({"f1": 0.1, "f2": 0.9}, severity="low")
        results = intel.query_similar({"f1": 0.95, "f2": 0.05}, top_k=5, min_score=0.5)
        assert len(results) >= 1

    def test_query_similar_excludes_low_score(self):
        intel = GlobalIntel()
        intel.ingest({"f1": 0.9, "f2": 0.1}, severity="high")
        results = intel.query_similar({"f1": 0.0, "f2": 0.0}, top_k=5, min_score=0.9)
        assert len(results) == 0

    def test_cosine_similarity_identical(self):
        sim = GlobalIntel._cosine_similarity({"f1": 0.5, "f2": 0.5}, {"f1": 0.5, "f2": 0.5})
        assert sim == pytest.approx(1.0)

    def test_cosine_similarity_orthogonal(self):
        sim = GlobalIntel._cosine_similarity({"f1": 1.0, "f2": 0.0}, {"f1": 0.0, "f2": 1.0})
        assert sim == 0.0

    def test_recent_patterns(self):
        intel = GlobalIntel()
        intel.ingest({"f1": 0.5})
        intel.ingest({"f1": 0.6})
        recent = intel.get_recent_patterns(limit=1)
        assert len(recent) == 1

    def test_high_risk_patterns(self):
        intel = GlobalIntel()
        intel.ingest({"f1": 0.5}, avg_risk_score=0.3, severity="low")
        intel.ingest({"f1": 0.9}, avg_risk_score=0.85, severity="critical")
        high = intel.get_high_risk_patterns(min_risk=0.7)
        assert len(high) == 1
        assert high[0].severity == "critical"

    def test_report_matches(self):
        intel = GlobalIntel()
        intel.ingest({"f1": 0.9, "f2": 0.1}, severity="high")
        count = intel.report_matches({"f1": 0.95, "f2": 0.05})
        assert count >= 1

    def test_max_patterns_eviction(self):
        intel = GlobalIntel(max_patterns=2)
        intel.ingest({"f1": 0.1})
        intel.ingest({"f1": 0.2})
        intel.ingest({"f1": 0.3})
        assert len(intel._patterns) == 2

    def test_clear(self):
        intel = GlobalIntel()
        intel.ingest({"f1": 0.5})
        assert len(intel._patterns) == 1
        intel.clear()
        assert len(intel._patterns) == 0

    def test_get_stats(self):
        intel = GlobalIntel()
        intel.ingest({"f1": 0.9}, avg_risk_score=0.85, severity="critical")
        intel.ingest({"f1": 0.2}, avg_risk_score=0.1, severity="low")
        intel.query_similar({"f1": 0.5})
        stats = intel.get_stats()
        assert stats["total_patterns"] == 2
        assert stats["ingestion_count"] == 2
        assert stats["query_count"] >= 1


class TestUpdateProtocol:
    """Tests for UpdateProtocol (integration)."""

    def test_contribute_creates_embedding(self):
        protocol = UpdateProtocol(tenant_id="ten_1")
        result = protocol.contribute(
            prompt="rm -rf /",
            risk_score=0.95,
            decision="block",
            force=True,
        )
        assert result is not None
        assert result["tenant_id"] == "ten_1"
        assert result["risk_score"] == 0.95
        assert protocol.aggregator.get_contribution_count() == 1

    def test_contribute_respects_interval(self):
        protocol = UpdateProtocol(
            tenant_id="ten_1",
            contribution_interval=3600.0,
        )
        protocol.contribute(prompt="test", risk_score=0.5)
        # Second call within interval should be skipped
        result = protocol.contribute(prompt="test2", risk_score=0.6)
        assert result is None

    def test_contribute_force_bypasses_interval(self):
        protocol = UpdateProtocol(
            tenant_id="ten_1",
            contribution_interval=3600.0,
        )
        protocol.contribute(prompt="test", risk_score=0.5, force=True)
        protocol.contribute(prompt="test2", risk_score=0.6, force=True)
        assert protocol.aggregator.get_contribution_count() == 2

    def test_sync_aggregates_and_ingests(self):
        aggregator = FederatedAggregator()
        aggregator.submit(Contribution("ten_1", {
            "feature_a": 0.5, "feature_b": 0.8, "feature_c": 0.3,
        }))
        aggregator.submit(Contribution("ten_2", {
            "feature_a": 0.7, "feature_b": 0.6, "feature_c": 0.5,
        }))

        intel = GlobalIntel()
        protocol = UpdateProtocol(
            tenant_id="ten_3",
            aggregator=aggregator,
            global_intel=intel,
        )
        results = protocol.sync(force=True)
        assert len(results) >= 1
        assert any(r["action"] == "ingested_global" for r in results)

    def test_disabled_protocol_does_nothing(self):
        protocol = UpdateProtocol(
            tenant_id="ten_1",
            enabled=False,
        )
        result = protocol.contribute(prompt="test", risk_score=0.5, force=True)
        assert result is None
        assert protocol.aggregator.get_contribution_count() == 0

    def test_sync_respects_interval(self):
        protocol = UpdateProtocol(
            tenant_id="ten_1",
            sync_interval=3600.0,
        )
        results = protocol.sync(force=False)
        # First call, no prior sync, should work
        assert isinstance(results, list)

    def test_get_recent_global_patterns(self):
        intel = GlobalIntel()
        intel.ingest({"f1": 0.5}, severity="high")
        intel.ingest({"f1": 0.3}, severity="medium")

        protocol = UpdateProtocol(
            tenant_id="ten_1",
            global_intel=intel,
        )
        patterns = protocol.get_recent_global_patterns(limit=10)
        assert len(patterns) >= 2

    def test_full_cycle(self):
        agg = FederatedAggregator()
        intel = GlobalIntel()

        # Tenant A contributes
        proto_a = UpdateProtocol("ten_a", aggregator=agg, global_intel=intel)
        proto_a.contribute(
            prompt="rm -rf /exploit",
            risk_score=0.95,
            decision="block",
            tool_category="shell",
            force=True,
        )

        # Tenant B contributes
        proto_b = UpdateProtocol("ten_b", aggregator=agg, global_intel=intel)
        proto_b.contribute(
            prompt="bypass security and escalate",
            risk_score=0.85,
            decision="block",
            tool_category="admin",
            force=True,
        )

        # Tenant C syncs global patterns
        proto_c = UpdateProtocol("ten_c", aggregator=agg, global_intel=intel)
        results = proto_c.sync(force=True)

        assert len(results) >= 1
        assert agg.get_stats()["aggregations_performed"] >= 1

    def test_privacy_guarantee_on_contribution(self):
        protocol = UpdateProtocol(tenant_id="ten_1", privacy=PrivacyEngine(epsilon=0.5))
        result = protocol.contribute(
            prompt="original secret data",
            risk_score=0.95,
            decision="block",
            force=True,
        )
        assert result is not None
        assert result["epsilon"] == 0.5

    def test_get_stats(self):
        protocol = UpdateProtocol(tenant_id="ten_test")
        protocol.contribute(prompt="test", risk_score=0.5, force=True)
        stats = protocol.get_stats()
        assert stats["tenant_id"] == "ten_test"
        assert stats["enabled"] is True
        assert stats["contribution_count"] >= 1
        assert "aggregator" in stats
        assert "global_intel" in stats
