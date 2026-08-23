"""
Adaptive Binary Search Prober for Transition Boundary Refinement.
"""

from typing import Callable, Awaitable, Tuple, List, Dict, Any, Union
import asyncio
import time
import math


class AdaptiveProber:
    def __init__(self, target_ms: float = 100.0, max_depth: int = 10):
        self.target_ms = target_ms
        self.target_sec = target_ms / 1000.0
        self.max_depth = max_depth

    async def refine_boundary(
        self,
        t_fault: float,
        t_last_unauth: float,
        t_first_block: float,
        probe_func: Callable[[float], Awaitable[Union[bool, Tuple[str, int, float, float]]]],
    ) -> Tuple[float, float, List[Dict[str, Any]]]:
        """
        Executes binary search probing between t_last_unauth and t_first_block down to target_ms precision.
        probe_func(target_offset_sec) -> returns (decision_str, status_code, latency_ms, actual_monotonic_timestamp).
        Returns updated (t_last_unauth, t_first_block, adaptive_probe_records).
        """
        left = t_last_unauth
        right = t_first_block
        adaptive_records: List[Dict[str, Any]] = []

        initial_interval = right - left
        if initial_interval > self.target_sec:
            required_iterations = math.ceil(math.log2(initial_interval / self.target_sec))
            iterations = max(self.max_depth, required_iterations)
        else:
            iterations = self.max_depth

        for i in range(iterations):
            interval = right - left
            if interval <= self.target_sec:
                break

            mid_t = (left + right) / 2.0
            mid_offset = max(0.0, mid_t - t_fault)

            raw_res = await probe_func(mid_offset)

            if isinstance(raw_res, tuple):
                if len(raw_res) == 4:
                    dec_str, status_code, lat_ms, actual_t = raw_res
                elif len(raw_res) == 3:
                    dec_bool, status_code, lat_ms = raw_res
                    dec_str = "ALLOW" if dec_bool else "DENY"
                    actual_t = mid_t
                else:
                    dec_str = "ALLOW" if raw_res[0] else "DENY"
                    status_code = 200 if dec_str == "ALLOW" else 403
                    lat_ms = 0.0
                    actual_t = mid_t
            else:
                dec_str = "ALLOW" if bool(raw_res) else "DENY"
                status_code = 200 if dec_str == "ALLOW" else 403
                lat_ms = 0.0
                actual_t = mid_t

            adaptive_records.append({
                "probe_index": 1000 + i + 1,
                "offset_target": mid_offset,
                "monotonic_timestamp": actual_t,
                "actual_decision": dec_str,
                "http_status": status_code,
                "latency_ms": lat_ms,
                "is_adaptive": True,
            })

            if dec_str == "ALLOW":
                left = actual_t
            elif dec_str == "DENY":
                right = actual_t
            else:
                # ERROR state: Abort refinement immediately to prevent corrupted boundary math
                break

        return left, right, adaptive_records
