"""
AuthTime Load Testing CLI Runner.
Executes high-concurrency stress tests against multi-replica targets during active revocation.
"""

import sys
import os
from pathlib import Path

repo_root = str(Path(__file__).resolve().parent.parent)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

import argparse
import asyncio
from typing import List
from src.authtime.load_testing import ConcurrentLoadTester


async def main_async(args: argparse.Namespace) -> None:
    base_urls = [url.strip() for url in args.urls.split(",") if url.strip()]
    token = args.token or "mock-jwt-token"

    print(f"======================================================================")
    print(f" [AUTHTIME HIGH-CONCURRENCY LOAD TEST]")
    print(f" Target Replicas : {base_urls}")
    print(f" Concurrency     : {args.concurrency} workers")
    print(f" Duration        : {args.duration}s")
    print(f" Probe Interval  : {args.interval}ms")
    print(f"======================================================================")

    tester = ConcurrentLoadTester(
        base_urls=base_urls,
        token=token,
        concurrency=args.concurrency,
        duration_sec=args.duration,
        probe_interval_ms=args.interval,
    )

    metrics = await tester.run_load_test()

    print(f"\n--- LOAD TEST RESULTS ---")
    print(f" Total Probes Completed : {metrics['total_probes']}")
    print(f" Throughput             : {metrics['rps']} RPS")
    print(f" ALLOW Decisions        : {metrics['allow_count']}")
    print(f" DENY Decisions         : {metrics['deny_count']}")
    print(f" Errors                 : {metrics['error_count']}")
    print(f" P50 Latency            : {metrics['latency_p50_ms']} ms")
    print(f" P95 Latency            : {metrics['latency_p95_ms']} ms")
    print(f" P99 Latency            : {metrics['latency_p99_ms']} ms")
    print(f" Mean Latency           : {metrics['latency_mean_ms']} ms")
    print(f" Exposure Window        : {metrics['exposure_sec']}s")
    print(f"======================================================================\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="AuthTime Load Testing CLI")
    parser.add_argument("--urls", type=str, default="http://127.0.0.1:8010,http://127.0.0.1:8011,http://127.0.0.1:8012", help="Comma-separated target replica URLs")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent probing workers")
    parser.add_argument("--duration", type=float, default=3.0, help="Test duration in seconds")
    parser.add_argument("--interval", type=int, default=20, help="Probe interval in ms per worker")
    parser.add_argument("--token", type=str, default="", help="JWT bearer token")

    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
