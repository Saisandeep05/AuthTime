"""
Adaptive Binary Search Prober for Transition Boundary Refinement.
"""

from typing import Callable, Awaitable, Tuple
import asyncio
import time


class AdaptiveProber:
    def __init__(self, target_ms: float = 100.0, max_depth: int = 5):
        self.target_ms = target_ms
        self.target_sec = target_ms / 1000.0
        self.max_depth = max_depth

    async def refine_boundary(
        self,
        t_fault: float,
        t_last_unauth: float,
        t_first_block: float,
        probe_func: Callable[[float], Awaitable[bool]],
    ) -> Tuple[float, float, int]:
        """
        Executes binary search probing between t_last_unauth and t_first_block.
        probe_func(target_offset_sec) -> returns is_unauth_allowed (True if ALLOW, False if BLOCK).
        Returns updated (t_last_unauth, t_first_block, additional_probes_fired).
        """
        left = t_last_unauth
        right = t_first_block
        probes_fired = 0

        for _ in range(self.max_depth):
            interval = right - left
            if interval <= self.target_sec:
                break

            mid_t = (left + right) / 2.0
            mid_offset = max(0.0, mid_t - t_fault)

            is_unauth_allowed = await probe_func(mid_offset)
            probes_fired += 1

            if is_unauth_allowed:
                left = mid_t
            else:
                right = mid_t

        return left, right, probes_fired
