"""
Verification & Timing Harness.

Executes async HTTP probes with monotonic precision and computes exposure window metrics.
"""

from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone
import math
from authtime.models.schemas import ProbeResult, ExposureMetric, GroundTruthState
from authtime.ground_truth.manager import ground_truth_manager


class VerificationHarness:
    @staticmethod
    def calculate_exposure_metrics(
        t_fault: float,
        probes: List[ProbeResult],
        scheduler_jitter_ms: float = 0.0,
        target_ms: float = 100.0,
    ) -> ExposureMetric:
        """
        Calculates Exposure Window metrics according to unified formulas:
        - t_fault: Revocation timestamp
        - t_first_unauth: First observed unauthorized access (ALLOW post-revocation)
        - t_last_unauth: Last observed unauthorized access (ALLOW post-revocation)
        - t_first_block: First reliably blocked access (BLOCK post-revocation)
        - Exposure Interval: [t_last_unauth - t_fault, t_first_block - t_fault]
        - estimated_exposure: ((t_last_unauth - t_fault) + (t_first_block - t_fault)) / 2
        - precision: (t_first_block - t_last_unauth) / 2
        """
        post_fault_probes = [p for p in probes if p.monotonic_timestamp >= t_fault]
        unauth_probes = [p for p in post_fault_probes if p.is_violation]
        blocked_probes = [p for p in post_fault_probes if not p.is_violation]

        first_unauth_t = unauth_probes[0].monotonic_timestamp if unauth_probes else None
        last_unauth_t = unauth_probes[-1].monotonic_timestamp if unauth_probes else None
        first_blocked_t = blocked_probes[0].monotonic_timestamp if blocked_probes else None

        if unauth_probes and blocked_probes:
            exposure_min = last_unauth_t - t_fault
            exposure_max = first_blocked_t - t_fault
            estimated_exposure = ((last_unauth_t - t_fault) + (first_blocked_t - t_fault)) / 2.0
            precision = (first_blocked_t - last_unauth_t) / 2.0
        elif unauth_probes and not blocked_probes:
            exposure_min = last_unauth_t - t_fault
            exposure_max = last_unauth_t - t_fault
            estimated_exposure = last_unauth_t - t_fault
            precision = 0.0
        else:
            exposure_min = 0.0
            exposure_max = 0.0
            estimated_exposure = 0.0
            precision = 0.0

        jitter_warn = None
        if scheduler_jitter_ms > target_ms:
            jitter_warn = "Measurement precision may be limited by scheduler overhead, not target-system behavior."

        return ExposureMetric(
            fault_timestamp_monotonic=t_fault,
            first_unauth_monotonic=first_unauth_t,
            last_unauth_monotonic=last_unauth_t,
            first_blocked_monotonic=first_blocked_t,
            exposure_interval_min_sec=max(0.0, exposure_min),
            exposure_interval_max_sec=max(0.0, exposure_max),
            estimated_exposure_sec=max(0.0, estimated_exposure),
            precision_sec=max(0.0, precision),
            scheduler_jitter_ms=scheduler_jitter_ms,
            jitter_warning=jitter_warn,
            unauthorized_request_count=len(unauth_probes),
            total_probes_fired=len(probes),
        )
