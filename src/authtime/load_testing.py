"""
AuthTime Load Testing & High-Concurrency Probing Engine.
Simulates multi-user concurrent HTTP probing during active revocation to measure throughput, P50/P95/P99 latency, and exposure windows under stress.
"""

import time
import asyncio
import statistics
import httpx
from typing import Dict, Any, List, Optional


class ConcurrentLoadTester:
    """
    High-concurrency authorization load testing orchestrator.
    Generates concurrent HTTP traffic against protected replica endpoints during revocation events.
    """

    def __init__(
        self,
        base_urls: List[str],
        token: str,
        target_user_id: str = "alice",
        concurrency: int = 10,
        duration_sec: float = 5.0,
        probe_interval_ms: int = 20,
    ):
        self.base_urls = base_urls
        self.token = token
        self.target_user_id = target_user_id
        self.concurrency = concurrency
        self.duration_sec = duration_sec
        self.probe_interval_sec = probe_interval_ms / 1000.0
        self.probes: List[Dict[str, Any]] = []
        self.latencies_ms: List[float] = []

    async def _worker(self, worker_id: int, stop_event: asyncio.Event, client: httpx.AsyncClient) -> None:
        """Individual worker probing loop."""
        replica_idx = worker_id % len(self.base_urls)
        target_url = f"{self.base_urls[replica_idx]}/finance/payroll"
        headers = {"Authorization": f"Bearer {self.token}"}

        while not stop_event.is_set():
            t_send = time.monotonic()
            try:
                resp = await client.get(target_url, headers=headers, timeout=2.0)
                t_recv = time.monotonic()
                latency_ms = (t_recv - t_send) * 1000.0
                self.latencies_ms.append(latency_ms)

                status_code = resp.status_code
                data = resp.json() if status_code in (200, 403) else {}
                decision = data.get("decision", "ALLOW" if status_code == 200 else "DENY" if status_code == 403 else "UNKNOWN")

                self.probes.append({
                    "worker_id": worker_id,
                    "replica_id": data.get("replica_id", f"api-{replica_idx + 1}"),
                    "timestamp_monotonic": t_send,
                    "latency_ms": latency_ms,
                    "status_code": status_code,
                    "decision": decision,
                    "role_evaluated": data.get("role_evaluated", "UNKNOWN"),
                })
            except Exception as e:
                t_recv = time.monotonic()
                self.probes.append({
                    "worker_id": worker_id,
                    "replica_id": f"api-{replica_idx + 1}",
                    "timestamp_monotonic": t_send,
                    "latency_ms": (t_recv - t_send) * 1000.0,
                    "status_code": 0,
                    "decision": "ERROR",
                    "error": str(e),
                })

            await asyncio.sleep(self.probe_interval_sec)

    async def run_load_test(self, revocation_trigger_fn: Optional[Any] = None) -> Dict[str, Any]:
        """Run concurrent load test and optional mid-test revocation."""
        self.probes.clear()
        self.latencies_ms.clear()
        stop_event = asyncio.Event()

        limits = httpx.Limits(max_keepalive_connections=self.concurrency * 2, max_connections=self.concurrency * 4)
        async with httpx.AsyncClient(limits=limits) as client:
            workers = [
                asyncio.create_task(self._worker(i, stop_event, client))
                for i in range(self.concurrency)
            ]

            start_t = time.monotonic()
            t0: Optional[float] = None

            # Allow baseline traffic before revocation if trigger specified
            if revocation_trigger_fn:
                await asyncio.sleep(0.5)
                t0 = time.monotonic()
                await revocation_trigger_fn()

            remaining = self.duration_sec - (time.monotonic() - start_t)
            if remaining > 0:
                await asyncio.sleep(remaining)

            stop_event.set()
            await asyncio.gather(*workers, return_exceptions=True)

        return self._calculate_metrics(t0)

    def _calculate_metrics(self, t0: Optional[float] = None) -> Dict[str, Any]:
        total_probes = len(self.probes)
        if total_probes == 0:
            return {"total_probes": 0, "error": "No probes executed"}

        allow_count = sum(1 for p in self.probes if p["decision"] == "ALLOW")
        deny_count = sum(1 for p in self.probes if p["decision"] == "DENY")
        error_count = sum(1 for p in self.probes if p["decision"] == "ERROR")

        sorted_latencies = sorted(self.latencies_ms) if self.latencies_ms else [0.0]
        n_lat = len(sorted_latencies)
        p50 = sorted_latencies[int(n_lat * 0.50)]
        p95 = sorted_latencies[int(n_lat * 0.95)]
        p99 = sorted_latencies[int(n_lat * 0.99)] if n_lat >= 100 else sorted_latencies[-1]

        total_duration = self.duration_sec
        rps = total_probes / total_duration if total_duration > 0 else 0.0

        exposure_sec = 0.0
        if t0 is not None:
            post_t0_allows = [p for p in self.probes if p["timestamp_monotonic"] >= t0 and p["decision"] == "ALLOW"]
            if post_t0_allows:
                exposure_sec = max(p["timestamp_monotonic"] for p in post_t0_allows) - t0

        return {
            "total_probes": total_probes,
            "concurrency": self.concurrency,
            "rps": round(rps, 2),
            "allow_count": allow_count,
            "deny_count": deny_count,
            "error_count": error_count,
            "latency_p50_ms": round(p50, 2),
            "latency_p95_ms": round(p95, 2),
            "latency_p99_ms": round(p99, 2),
            "latency_mean_ms": round(statistics.mean(sorted_latencies), 2) if sorted_latencies else 0.0,
            "exposure_sec": round(exposure_sec, 4),
        }
