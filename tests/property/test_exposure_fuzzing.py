"""
Property-Based Fuzzing Suite for AuthTime Timing & Exposure Metric Calculator.
"""

import pytest
import random
import time
from authtime.models.schemas import ProbeResult, EvidenceEvent
from authtime.verification.harness import VerificationHarness


def generate_random_probe_sequence(exposure_duration: float, probe_interval: float):
    probes = []
    t_fault = 100.0
    t_expiry = t_fault + exposure_duration

    current_t = t_fault
    index = 0

    while current_t <= t_expiry + (probe_interval * 3):
        is_unauth = current_t < t_expiry
        probes.append(
            ProbeResult(
                request_id=f"req-fuzz-{index}",
                experiment_id="exp-fuzz-01",
                scenario_id="scenario-fuzz-01",
                utc_timestamp=time.time(),
                probe_index=index,
                offset_target=current_t - t_fault,
                monotonic_timestamp=current_t,
                http_status=200 if is_unauth else 403,
                actual_decision="ALLOW" if is_unauth else "DENY",
                ground_truth_decision="DENY",
                is_violation=is_unauth,
                response_latency_ms=random.uniform(1.0, 5.0),
            )
        )
        current_t += probe_interval
        index += 1

    return probes, t_fault, t_expiry


def test_property_exposure_metric_invariants():
    """Fuzzes exposure metrics over 100 randomized property iterations."""
    for iteration in range(100):
        exposure_duration = random.uniform(0.1, 30.0)
        probe_interval = random.uniform(0.1, 2.0)

        probes, t_fault, t_expiry = generate_random_probe_sequence(exposure_duration, probe_interval)

        metrics = VerificationHarness.calculate_exposure_metrics(
            t_fault=t_fault, probes=probes, scheduler_jitter_ms=1.5
        )

        # Invariant 1: Exposure must be non-negative
        assert metrics.estimated_exposure_sec >= 0.0, f"Negative exposure on iter {iteration}"

        # Invariant 2: Precision must be greater than 0
        assert metrics.precision_sec > 0.0, f"Invalid precision on iter {iteration}"

        # Invariant 3: Violation count must match unauth probe count
        unauth_count = sum(1 for p in probes if p.is_violation)
        assert metrics.unauthorized_request_count == unauth_count, f"Count mismatch on iter {iteration}"
