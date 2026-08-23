"""
Unit tests for exposure window mathematical calculations.
"""

from datetime import datetime, timezone
from authtime.models.schemas import ProbeResult
from authtime.verification.harness import VerificationHarness


def test_exposure_math_calculation():
    t_fault = 100.0

    probes = [
        # Pre-fault
        ProbeResult(
            request_id="req-1", experiment_id="exp-1", scenario_id="s1", probe_index=0, offset_target=-10.0,
            monotonic_timestamp=90.0, utc_timestamp=datetime.now(timezone.utc), http_status=200,
            actual_decision="ALLOW", ground_truth_decision="ALLOW", is_violation=False, response_latency_ms=5.0
        ),
        # Post-fault probe 1: ALLOW (violation)
        ProbeResult(
            request_id="req-2", experiment_id="exp-1", scenario_id="s1", probe_index=1, offset_target=0.1,
            monotonic_timestamp=100.1, utc_timestamp=datetime.now(timezone.utc), http_status=200,
            actual_decision="ALLOW", ground_truth_decision="DENY", is_violation=True, response_latency_ms=5.0
        ),
        # Post-fault probe 2: ALLOW (violation)
        ProbeResult(
            request_id="req-3", experiment_id="exp-1", scenario_id="s1", probe_index=2, offset_target=47.2,
            monotonic_timestamp=147.2, utc_timestamp=datetime.now(timezone.utc), http_status=200,
            actual_decision="ALLOW", ground_truth_decision="DENY", is_violation=True, response_latency_ms=5.0
        ),
        # Post-fault probe 3: BLOCK
        ProbeResult(
            request_id="req-4", experiment_id="exp-1", scenario_id="s1", probe_index=3, offset_target=60.1,
            monotonic_timestamp=160.1, utc_timestamp=datetime.now(timezone.utc), http_status=403,
            actual_decision="DENY", ground_truth_decision="DENY", is_violation=False, response_latency_ms=5.0
        ),
    ]

    metrics = VerificationHarness.calculate_exposure_metrics(
        t_fault=t_fault, probes=probes, scheduler_jitter_ms=2.5, target_ms=100.0
    )

    assert metrics.fault_timestamp_monotonic == 100.0
    assert metrics.first_unauth_monotonic == 100.1
    assert metrics.last_unauth_monotonic == 147.2
    assert metrics.first_blocked_monotonic == 160.1

    # exposure_interval = [147.2 - 100.0, 160.1 - 100.0] = [47.2, 60.1]
    assert abs(metrics.exposure_interval_min_sec - 47.2) < 1e-5
    assert abs(metrics.exposure_interval_max_sec - 60.1) < 1e-5

    # estimated_exposure = ((147.2 - 100.0) + (160.1 - 100.0)) / 2 = (47.2 + 60.1) / 2 = 53.65
    assert abs(metrics.estimated_exposure_sec - 53.65) < 1e-5

    # precision = (160.1 - 147.2) / 2 = 12.9 / 2 = 6.45
    assert abs(metrics.precision_sec - 6.45) < 1e-5

    assert metrics.unauthorized_request_count == 2
    assert metrics.jitter_warning is None
