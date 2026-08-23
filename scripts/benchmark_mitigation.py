"""
AuthTime Mitigation Performance Benchmarking Script.
Compares baseline JWT authorization throughput/latency against version-aware mitigation.
"""

import sys
import os
from pathlib import Path

repo_root = str(Path(__file__).resolve().parent.parent)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

import time
import asyncio
from typing import Dict, Any
from fastapi.testclient import TestClient
from targets.distributed_lab.service.app import create_lab_replica_app
from targets.distributed_lab.auth.jwt_handler import LabJWTHandler


def run_benchmark(num_requests: int = 1000) -> Dict[str, Any]:
    app = create_lab_replica_app(replica_id="api-1")
    client = TestClient(app)
    jwt_handler = LabJWTHandler()

    valid_token = jwt_handler.create_access_token("alice", role="Finance Admin", auth_version=1)
    headers = {"Authorization": f"Bearer {valid_token}"}

    print(f"======================================================================")
    print(f" [AUTHTIME MITIGATION PERFORMANCE BENCHMARK ({num_requests} REQS)]")
    print(f"======================================================================")

    # 1. Benchmark Identity / Baseline Endpoint
    latencies_baseline = []
    start_t = time.monotonic()
    for _ in range(num_requests):
        t0 = time.monotonic()
        resp = client.get("/health", headers=headers)
        t1 = time.monotonic()
        latencies_baseline.append((t1 - t0) * 1000.0)
    dur_baseline = time.monotonic() - start_t
    rps_baseline = num_requests / dur_baseline

    # 2. Benchmark Version-Aware Protected Endpoint
    latencies_versioned = []
    start_t = time.monotonic()
    for _ in range(num_requests):
        t0 = time.monotonic()
        resp = client.get("/finance/payroll", headers=headers)
        t1 = time.monotonic()
        latencies_versioned.append((t1 - t0) * 1000.0)
    dur_versioned = time.monotonic() - start_t
    rps_versioned = num_requests / dur_versioned

    latencies_baseline.sort()
    latencies_versioned.sort()

    p50_base = latencies_baseline[int(num_requests * 0.50)]
    p95_base = latencies_baseline[int(num_requests * 0.95)]

    p50_ver = latencies_versioned[int(num_requests * 0.50)]
    p95_ver = latencies_versioned[int(num_requests * 0.95)]

    overhead_ms = p50_ver - p50_base
    overhead_pct = ((rps_baseline - rps_versioned) / rps_baseline) * 100.0 if rps_baseline > 0 else 0.0

    print(f" Baseline Throughput       : {rps_baseline:.2f} RPS (P50: {p50_base:.2f}ms, P95: {p95_base:.2f}ms)")
    print(f" Version-Aware Throughput  : {rps_versioned:.2f} RPS (P50: {p50_ver:.2f}ms, P95: {p95_ver:.2f}ms)")
    print(f" Latency Overhead (P50)    : +{overhead_ms:.2f} ms per request")
    print(f" Throughput Cost           : {overhead_pct:.1f}%")
    print(f"======================================================================\n")

    return {
        "num_requests": num_requests,
        "rps_baseline": round(rps_baseline, 2),
        "rps_versioned": round(rps_versioned, 2),
        "p50_baseline_ms": round(p50_base, 2),
        "p95_baseline_ms": round(p95_base, 2),
        "p50_versioned_ms": round(p50_ver, 2),
        "p95_versioned_ms": round(p95_ver, 2),
        "overhead_p50_ms": round(overhead_ms, 2),
        "throughput_overhead_pct": round(overhead_pct, 1),
    }


if __name__ == "__main__":
    run_benchmark(1000)
