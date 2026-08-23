"""
Unit tests for Adaptive Binary Search Prober.
"""

import pytest
from authtime.verification.adaptive_prober import AdaptiveProber


@pytest.mark.asyncio
async def test_adaptive_binary_search():
    prober = AdaptiveProber(target_ms=100.0, max_depth=6)

    # Simulated app transition: ALLOW up to T=12.5s, BLOCK at T >= 12.5s
    transition_point = 112.5
    t_fault = 100.0

    async def mock_probe(offset: float) -> bool:
        probe_t = t_fault + offset
        return probe_t < transition_point

    t_last_unauth = 105.0
    t_first_block = 130.0

    left, right, count = await prober.refine_boundary(
        t_fault=t_fault,
        t_last_unauth=t_last_unauth,
        t_first_block=t_first_block,
        probe_func=mock_probe,
    )

    assert count > 0
    # The refined boundary interval (right - left) should be narrowed
    assert (right - left) <= 25.0
