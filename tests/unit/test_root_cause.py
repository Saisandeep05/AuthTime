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
        estimated_exposure_sec=60.0,
        precision_sec=0.1,
        scheduler_jitter_ms=1.5,
        unauthorized_request_count=5,
        total_probes_fired=10,
    )

    code, conf, expl = RootCauseAnalyzer.analyze_root_cause("stale_cache", {"cache_ttl_seconds": 60.0}, dummy_metric)
    assert code == "AUTHORIZATION_CACHE"
    assert conf in ("CONFIRMED", "SUPPORTED")

    code_col, conf_col, _ = RootCauseAnalyzer.analyze_root_cause("stale_cache", {}, dummy_metric, has_cache_key_collision=True)
    assert code_col == "CACHE_KEY_COLLISION"
    assert conf_col in ("CONFIRMED", "SUPPORTED")

    code_del, conf_del, _ = RootCauseAnalyzer.analyze_root_cause("session_delegation_revocation", {}, dummy_metric)
    assert code_del == "DELEGATED_CREDENTIAL_STALENESS"
    assert conf_del in ("SUPPORTED", "INFERRED")

