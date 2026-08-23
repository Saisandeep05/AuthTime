"""
Verification Harness & Exposure Window Calculator.
"""

import asyncio
import time
from typing import List, Optional
from authtime.models.schemas import ProbeResult, ExposureMetric


async def measure_scheduler_jitter(n_probes: int = 10, delay_ms: float = 2.0) -> float:
    delays = []
    target_sec = delay_ms / 1000.0
    for _ in range(n_probes):
        t0 = time.monotonic()
        await asyncio.sleep(target_sec)
        t1 = time.monotonic()
        delays.append(abs((t1 - t0) - target_sec) * 1000.0)
    return float(sum(delays) / len(delays)) if delays else 0.0


class VerificationHarness:
    @staticmethod
    def calculate_exposure_metrics(
        t_fault: float,
        probes: List[ProbeResult],
        scheduler_jitter_ms: float,
        target_ms: float = 100.0,
        total_window_sec: float = 60.0,
    ) -> ExposureMetric:
        sorted_probes = sorted(probes, key=lambda p: p.monotonic_timestamp)
        post_fault_unauth = [p for p in sorted_probes if p.monotonic_timestamp >= t_fault and p.is_violation]
        post_fault_blocks = [p for p in sorted_probes if p.monotonic_timestamp >= t_fault and not p.is_violation and p.actual_decision == "DENY"]


        t_first_unauth = post_fault_unauth[0].monotonic_timestamp if post_fault_unauth else None
        t_last_unauth = post_fault_unauth[-1].monotonic_timestamp if post_fault_unauth else None
        t_first_block = post_fault_blocks[0].monotonic_timestamp if post_fault_blocks else None

        is_censored = False
        measurement_status = "OBSERVED_TRANSITION"

        if t_last_unauth and t_first_block and t_first_block > t_last_unauth:
            exp_min = t_last_unauth - t_fault
            exp_max = t_first_block - t_fault
            est_exp = (exp_min + exp_max) / 2.0
            precision = (t_first_block - t_last_unauth) / 2.0
            measurement_status = "OBSERVED_TRANSITION"
        elif t_last_unauth:
            exp_min = t_last_unauth - t_fault
            exp_max = None
            est_exp = None  # Unbounded right-censored observation; exp_min represents lower bound!
            precision = None
            is_censored = True
            measurement_status = "CENSORED_LOWER_BOUND"
        else:
            exp_min = 0.0
            exp_max = 0.0
            est_exp = 0.0
            precision = 0.0
            measurement_status = "NO_EXPOSURE"

        jitter_warn = None
        if scheduler_jitter_ms > target_ms:
            jitter_warn = "Measurement precision may be limited by scheduler overhead, not target-system behavior."

        return ExposureMetric(
            fault_timestamp_monotonic=t_fault,
            first_unauth_monotonic=t_first_unauth,
            last_unauth_monotonic=t_last_unauth,
            first_blocked_monotonic=t_first_block,
            exposure_interval_min_sec=exp_min,
            exposure_interval_max_sec=exp_max,
            estimated_exposure_sec=est_exp,
            precision_sec=precision,
            observation_horizon_sec=total_window_sec,
            scheduler_jitter_ms=scheduler_jitter_ms,
            jitter_warning=jitter_warn,
            unauthorized_request_count=len(post_fault_unauth),
            total_probes_fired=len(probes),
            is_censored=is_censored,
            measurement_status=measurement_status,
        )
