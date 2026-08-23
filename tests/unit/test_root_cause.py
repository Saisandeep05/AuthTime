"""
Unit tests for RootCauseAnalyzer.
"""

from authtime.models.schemas import ExposureMetric
from authtime.verification.root_cause import RootCauseAnalyzer


def test_root_cause_classifications():
    dummy_metric = ExposureMetric(
        fault_timestamp_monotonic=0.0,
        exposure_interval_min_sec=0.0,
        exposure_interval_max_sec=0.0,
        estimated_exposure_sec=0.0,
        precision_sec=0.0,
        scheduler_jitter_ms=0.0,
        unauthorized_request_count=0,
        total_probes_fired=0,
    )

    code, conf, expl = RootCauseAnalyzer.analyze_root_cause("stale_cache", {"cache_ttl_seconds": 60.0}, dummy_metric)
    assert code == "AUTHORIZATION_CACHE"
    assert conf == "Likely"

    code_col, conf_col, _ = RootCauseAnalyzer.analyze_root_cause("stale_cache", {}, dummy_metric, has_cache_key_collision=True)
    assert code_col == "CACHE_KEY_COLLISION"
    assert conf_col == "High"

    code_agent, conf_agent, _ = RootCauseAnalyzer.analyze_root_cause("agent_session_revocation", {}, dummy_metric)
    assert code_agent == "DELEGATED_CREDENTIAL_STALENESS"
    assert conf_agent == "High"
