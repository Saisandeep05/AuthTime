"""
Unit tests for AdaptiveProber binary search logic.
"""

import pytest
from authtime.verification.adaptive_prober import AdaptiveProber


@pytest.mark.asyncio
async def test_adaptive_binary_search():
    prober = AdaptiveProber(target_ms=100.0, max_depth=5)
    t_fault = 100.0
    t_last_unauth = 105.0
    t_first_block = 110.0

    # True boundary is at t=107.0 (offset 7.0s)
    async def mock_probe_func(offset_sec: float) -> bool:
        probe_t = t_fault + offset_sec
        return probe_t < 107.0

    left, right, records = await prober.refine_boundary(t_fault, t_last_unauth, t_first_block, mock_probe_func)

    assert len(records) > 0
    assert left <= 107.0 <= right
    assert (right - left) <= 0.1
