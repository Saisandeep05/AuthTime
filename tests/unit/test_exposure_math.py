"""
Unit tests for exposure metrics timing math.
"""

from datetime import datetime, timezone
from authtime.models.schemas import ProbeResult
from authtime.verification.harness import VerificationHarness


def test_exposure_math_calculation():
    t_fault = 100.0
    utc_now = datetime.now(timezone.utc)

    probes = [
        ProbeResult(
            request_id="p1", experiment_id="exp1", scenario_id="scen1", probe_index=0,
            offset_target=0.0, monotonic_timestamp=100.1, utc_timestamp=utc_now,
            http_status=200, actual_decision="ALLOW", ground_truth_decision="DENY",
            is_violation=True, response_latency_ms=2.0
        ),
        ProbeResult(
            request_id="p2", experiment_id="exp1", scenario_id="scen1", probe_index=1,
            offset_target=5.0, monotonic_timestamp=105.0, utc_timestamp=utc_now,
            http_status=200, actual_decision="ALLOW", ground_truth_decision="DENY",
            is_violation=True, response_latency_ms=2.0
        ),
        ProbeResult(
            request_id="p3", experiment_id="exp1", scenario_id="scen1", probe_index=2,
            offset_target=10.0, monotonic_timestamp=110.0, utc_timestamp=utc_now,
            http_status=403, actual_decision="DENY", ground_truth_decision="DENY",
            is_violation=False, response_latency_ms=2.0
        ),
    ]

    metrics = VerificationHarness.calculate_exposure_metrics(t_fault, probes, scheduler_jitter_ms=1.5)
    assert metrics.first_unauth_monotonic == 100.1
    assert metrics.last_unauth_monotonic == 105.0
    assert metrics.first_blocked_monotonic == 110.0
    assert metrics.exposure_interval_min_sec == 5.0  # 105.0 - 100.0
    assert metrics.exposure_interval_max_sec == 10.0 # 110.0 - 100.0
    assert metrics.estimated_exposure_sec == 7.5
    assert metrics.precision_sec == 2.5
