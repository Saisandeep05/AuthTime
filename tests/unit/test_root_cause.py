"""
Unit tests for Root Cause Analyzer.
"""

from authtime.models.schemas import ExposureMetric
from authtime.verification.root_cause import RootCauseAnalyzer


def test_root_cause_analysis_types():
    metrics = ExposureMetric(
        fault_timestamp_monotonic=100.0,
        first_unauth_monotonic=100.1,
        last_unauth_monotonic=147.2,
        first_blocked_monotonic=160.1,
        exposure_interval_min_sec=47.2,
        exposure_interval_max_sec=60.1,
        estimated_exposure_sec=53.65,
        precision_sec=6.45,
        scheduler_jitter_ms=1.5,
        unauthorized_request_count=10,
        total_probes_fired=15,
    )

    code1, conf1, _ = RootCauseAnalyzer.analyze_root_cause("stale_cache", {"cache_ttl_seconds": 60.0}, metrics)
    assert code1 == "AUTHORIZATION_CACHE"
    assert conf1 == "Likely"

    code2, conf2, _ = RootCauseAnalyzer.analyze_root_cause("role_revocation", {}, metrics, has_cache_key_collision=True)
    assert code2 == "CACHE_KEY_COLLISION"
    assert conf2 == "High"

    code3, conf3, _ = RootCauseAnalyzer.analyze_root_cause("agent_session_revocation", {}, metrics)
    assert code3 == "DELEGATED_CREDENTIAL_STALENESS"
    assert conf3 == "High"
