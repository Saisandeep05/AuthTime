"""
High-Precision Monotonic Clock & Harness Scheduler Calibration.
"""

import time
import asyncio


def get_monotonic_time() -> float:
    """Returns Python's high-precision monotonic clock timestamp."""
    return time.monotonic()


async def measure_scheduler_jitter(n_probes: int = 20, delay_ms: float = 2.0) -> float:
    """
    Measures harness scheduling overhead across a calibration burst of no-op delays.
    Returns average absolute deviation between intended delay and actual elapsed time in ms.
    """
    deviations = []
    delay_sec = delay_ms / 1000.0

    for _ in range(n_probes):
        start = time.monotonic()
        await asyncio.sleep(delay_sec)
        actual_elapsed = time.monotonic() - start
        dev_ms = abs(actual_elapsed - delay_sec) * 1000.0
        deviations.append(dev_ms)

    if not deviations:
        return 0.0

    return sum(deviations) / len(deviations)
