"""
AuthTime Long-Run Reliability & Endurance Test Script.
Runs continuous cycles of login, role revocation, cache invalidation, and state reconciliation over configurable duration.
"""

import sys
import os
from pathlib import Path

repo_root = str(Path(__file__).resolve().parent.parent)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

import time
import argparse
import asyncio
from typing import Dict, Any
from fastapi.testclient import TestClient
from targets.distributed_lab.service.app import create_lab_replica_app
from targets.distributed_lab.auth.jwt_handler import LabJWTHandler


def run_endurance_test(duration_sec: float = 60.0) -> Dict[str, Any]:
    app = create_lab_replica_app(replica_id="api-1")
    client = TestClient(app)
    jwt_handler = LabJWTHandler()

    print(f"======================================================================")
    print(f" [AUTHTIME LONG-RUN RELIABILITY & ENDURANCE TEST]")
    print(f" Test Duration: {duration_sec:.1f}s")
    print(f"======================================================================")

    start_t = time.monotonic()
    cycle_count = 0
    total_probes = 0
    errors = 0

    while (time.monotonic() - start_t) < duration_sec:
        cycle_count += 1
        # Step 0: Ensure DB state is baseline
        client.post("/reset", params={"broadcast": "false"})

        # Step 1: Issue token & verify pre-revocation baseline
        token = jwt_handler.create_access_token("alice", role="Finance Admin", auth_version=cycle_count)
        headers = {"Authorization": f"Bearer {token}"}

        resp = client.get("/finance/payroll", headers=headers)
        total_probes += 1
        if resp.status_code != 200:
            errors += 1

        # Step 2: Trigger revocation
        client.post("/faults/revoke", json={"user_id": "alice", "new_role": "User"}, params={"broadcast": "false"})

        # Step 3: Verify immediate post-revocation authoritative denial
        resp = client.get("/finance/payroll", headers=headers)
        total_probes += 1
        if resp.status_code != 403:
            errors += 1
        time.sleep(0.05)

    elapsed = time.monotonic() - start_t
    print(f"\n--- ENDURANCE TEST RESULTS ---")
    print(f" Total Duration      : {elapsed:.2f}s")
    print(f" Completed Cycles    : {cycle_count}")
    print(f" Total Probes        : {total_probes}")
    print(f" Encountered Errors  : {errors}")
    print(f" Cycle Success Rate  : {((total_probes - errors) / total_probes) * 100.0:.2f}%")
    print(f"======================================================================\n")

    return {
        "duration_sec": round(elapsed, 2),
        "cycles": cycle_count,
        "total_probes": total_probes,
        "errors": errors,
        "success_rate_pct": round(((total_probes - errors) / total_probes) * 100.0, 2),
    }


def main():
    parser = argparse.ArgumentParser(description="AuthTime Endurance Test CLI")
    parser.add_argument("--duration", type=float, default=10.0, help="Test duration in seconds")
    args = parser.parse_args()
    run_endurance_test(args.duration)


if __name__ == "__main__":
    main()
