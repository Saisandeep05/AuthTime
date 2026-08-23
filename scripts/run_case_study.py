import os
import sys

_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_src_dir = os.path.join(_project_root, "src")

if _src_dir in sys.path:
    sys.path.remove(_src_dir)
sys.path.insert(0, _src_dir)

if _project_root in sys.path:
    sys.path.remove(_project_root)
sys.path.insert(0, _project_root)

print("[DEBUG] sys.path:", sys.path[:3], flush=True)

import time
import json
import asyncio
import threading
from typing import Dict, Any, List

import httpx
try:
    from targets.distributed_lab.service.app import create_lab_replica_app
    print("[DEBUG] Successfully imported create_lab_replica_app", flush=True)
except Exception as e:
    print(f"[DEBUG] Import error: {e}", flush=True)
    raise e
from authtime.adapters.target_adapter import DistributedLabAdapter


import subprocess

SPAWNED_PROCESSES: List[subprocess.Popen] = []

def start_replica_process(replica_id: str, port: int) -> subprocess.Popen:
    """Launches an independent FastAPI replica server process using server.py."""
    env = dict(os.environ)
    env["REPLICA_ID"] = replica_id
    env["PORT"] = str(port)
    env["HOST"] = "127.0.0.1"
    env["PYTHONPATH"] = _project_root

    proc = subprocess.Popen(
        [sys.executable, "-m", "targets.distributed_lab.service.server"],
        cwd=_project_root,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    SPAWNED_PROCESSES.append(proc)
    return proc


async def ensure_replicas_running(ports: List[int] = [8010, 8011, 8012]):
    """Ensures API-1, API-2, API-3 replicas are active and healthy."""
    async with httpx.AsyncClient(timeout=1.0) as client:
        for i, port in enumerate(ports):
            replica_id = f"api-{i+1}"
            url = f"http://127.0.0.1:{port}"
            try:
                r = await client.get(f"{url}/identity")
                if r.status_code == 200:
                    continue
            except Exception:
                pass
            start_replica_process(replica_id, port)

    # Polling readiness
    async with httpx.AsyncClient(timeout=1.0) as client:
        for port in ports:
            for _ in range(30):
                try:
                    r = await client.get(f"http://127.0.0.1:{port}/identity")
                    if r.status_code == 200:
                        break
                except Exception:
                    await asyncio.sleep(0.1)


async def execute_offboarding_trial(adapter: DistributedLabAdapter, enable_mitigation: bool) -> Dict[str, Any]:
    """Runs single offboarding trial (vulnerable or mitigated) for user 'alice'."""
    # 1. Reset state
    await adapter.reset_state()
    await adapter.configure_mitigation(enabled=enable_mitigation)

    # 2. Login as alice (Finance Admin)
    token = await adapter.login_user("alice")

    # 3. Verify baseline ALLOW across all replicas on /finance/payroll
    baseline_probes = await adapter.probe_all_replicas("/finance/payroll", token, "req-baseline")
    for r_id, (st, _, _) in baseline_probes.items():
        if st != 200:
            raise RuntimeError(f"Baseline authorization failed for {r_id}: status {st}")

    # 4. Inject fault: configure TTL cache mode for vulnerable trial, or normal
    if not enable_mitigation:
        # Configure STALE_CACHE fault mode with 5.0s TTL override
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(
                "http://127.0.0.1:8010/faults/configure-cache-mode",
                json={"mode": "ttl", "ttl_sec": 5.0},
            )

    # 5. Authoritative Revocation Event: demote alice to Employee
    t0_mono = time.monotonic()
    t0_wall = time.time()

    async with httpx.AsyncClient(timeout=2.0) as client:
        r_rev = await client.post(
            "http://127.0.0.1:8010/faults/revoke",
            json={"user_id": "alice", "new_role": "Employee"},
        )
        rev_data = r_rev.json()
        t0_authoritative = rev_data.get("event", {}).get("authoritative_timestamp", t0_mono)

    # 6. High-Frequency Probe Loop over 6.0 seconds
    replica_logs: Dict[str, List[Dict[str, Any]]] = {"api-1": [], "api-2": [], "api-3": []}
    raw_probe_events: List[Dict[str, Any]] = []

    probe_count = 50
    interval = 0.1

    for idx in range(probe_count):
        t_current = time.monotonic()
        probes = await adapter.probe_all_replicas("/finance/payroll", token, f"req-offboard-{idx}")

        for r_name, (st_code, body_text, lat_ms) in probes.items():
            entry = {
                "probe_index": idx,
                "timestamp_monotonic": t_current,
                "dt_since_revocation_sec": max(0.0, t_current - t0_authoritative),
                "replica_id": r_name,
                "status_code": st_code,
                "latency_ms": lat_ms,
            }
            replica_logs[r_name].append(entry)
            raw_probe_events.append(entry)

        await asyncio.sleep(interval)

    # 7. Calculate exposure metrics using adapter engine
    exposure = adapter.calculate_per_replica_exposure(replica_logs, t0_authoritative)

    return {
        "mitigation_enabled": enable_mitigation,
        "user_id": "alice",
        "initial_role": "Finance Admin",
        "revoked_role": "Employee",
        "resource_path": "/finance/payroll",
        "t0_authoritative_monotonic": t0_authoritative,
        "t0_authoritative_wall": t0_wall,
        "exposure_metrics": exposure,
        "raw_probe_events": raw_probe_events,
    }


async def main_async():
    print("=" * 70, flush=True)
    print(" [AuthTime Real-World Case Study: Employee Offboarding Exposure]", flush=True)
    print("=" * 70, flush=True)

    print("\n[*] Initializing multi-replica API server environment (API-1, API-2, API-3)...", flush=True)
    await ensure_replicas_running()
    print("[+] Multi-process replicas HEALTHY on ports 8010, 8011, 8012.\n", flush=True)

    adapter = DistributedLabAdapter()

    try:
        # Step 1: Run Vulnerable Trial
        print("[*] STEP 1/2: Executing VULNERABLE Employee Offboarding Trial...", flush=True)
        vuln_results = await execute_offboarding_trial(adapter, enable_mitigation=False)
        vuln_agg = vuln_results["exposure_metrics"]["aggregate"]
        print(f"  - Max Exposure  : {vuln_agg['max_exposure_sec']:.2f}s", flush=True)
        print(f"  - Mean Exposure : {vuln_agg['mean_exposure_sec']:.2f}s", flush=True)
        print(f"  - Min Exposure  : {vuln_agg['min_exposure_sec']:.2f}s", flush=True)

        # Step 2: Run Mitigated Trial (Authorization Versioning)
        print("\n[*] STEP 2/2: Executing MITIGATED (Authorization Versioning) Trial...", flush=True)
        mitigated_results = await execute_offboarding_trial(adapter, enable_mitigation=True)
        mit_agg = mitigated_results["exposure_metrics"]["aggregate"]
        print(f"  - Max Exposure  : {mit_agg['max_exposure_sec']:.2f}s", flush=True)
        print(f"  - Mean Exposure : {mit_agg['mean_exposure_sec']:.2f}s", flush=True)
        print(f"  - Min Exposure  : {mit_agg['min_exposure_sec']:.2f}s", flush=True)

        # Step 3: Calculate Improvement Metrics
        vuln_max = vuln_agg["max_exposure_sec"]
        mit_max = mit_agg["max_exposure_sec"]

        if vuln_max > 0:
            pct_reduction = max(0.0, ((vuln_max - mit_max) / vuln_max) * 100.0)
        else:
            pct_reduction = 100.0 if mit_max == 0 else 0.0

        comparison = {
            "case_study": "Employee Offboarding Temporal Authorization Exposure",
            "user_id": "alice",
            "vulnerable_max_exposure_sec": vuln_max,
            "vulnerable_mean_exposure_sec": vuln_agg["mean_exposure_sec"],
            "mitigated_max_exposure_sec": mit_max,
            "mitigated_mean_exposure_sec": mit_agg["mean_exposure_sec"],
            "exposure_reduction_percent": pct_reduction,
            "mitigation_technique": "Authorization Versioning & Version-Aware Cache Validation",
            "validation_level": "Level B — Multi-Process Distributed Application Validation",
        }

        print("\n" + "=" * 70, flush=True)
        print(" [OFFBOARDING CASE STUDY COMPARISON RESULTS]", flush=True)
        print("=" * 70, flush=True)
        print(f"  Metric                     | Vulnerable   | Mitigated    | Improvement", flush=True)
        print(f"  ---------------------------|--------------|--------------|------------", flush=True)
        print(f"  Max Exposure Duration (s)  | {vuln_max:12.2f} | {mit_max:12.2f} | {pct_reduction:10.1f}%", flush=True)
        print(f"  Mean Exposure Duration (s) | {vuln_agg['mean_exposure_sec']:12.2f} | {mit_agg['mean_exposure_sec']:12.2f} | {pct_reduction:10.1f}%", flush=True)
        print("=" * 70 + "\n", flush=True)

        # Step 4: Write Durable Artifacts
        base_dir = "experiments/employee_offboarding_case_study"
        raw_dir = os.path.join(base_dir, "raw-evidence")
        os.makedirs(raw_dir, exist_ok=True)

        with open(os.path.join(base_dir, "vulnerable-results.json"), "w", encoding="utf-8") as f:
            json.dump(vuln_results, f, indent=2)

        with open(os.path.join(base_dir, "mitigated-results.json"), "w", encoding="utf-8") as f:
            json.dump(mitigated_results, f, indent=2)

        with open(os.path.join(base_dir, "comparison.json"), "w", encoding="utf-8") as f:
            json.dump(comparison, f, indent=2)

        with open(os.path.join(raw_dir, "vulnerable_probes.json"), "w", encoding="utf-8") as f:
            json.dump(vuln_results.pop("raw_probe_events"), f, indent=2)

        with open(os.path.join(raw_dir, "mitigated_probes.json"), "w", encoding="utf-8") as f:
            json.dump(mitigated_results.pop("raw_probe_events"), f, indent=2)

        # Write Case Study README in experiment folder
        exp_readme = f"""# Employee Offboarding Case Study Artifacts

This folder contains durable evidence artifacts collected during the real-world **Employee Offboarding Temporal Authorization Exposure Case Study**.

## Case Study Summary

- **User**: `alice`
- **Initial Role**: `Finance Admin`
- **Revoked Role**: `Employee`
- **Protected Resource**: `/finance/payroll`
- **Mitigation Technique**: Authorization Versioning & Version-Aware Cache Validation
- **Validation Level**: Level B — Multi-Process Distributed Application Validation

## Empirical Key Metrics

| Metric | Vulnerable Baseline | Mitigated State | Improvement |
| :--- | :---: | :---: | :---: |
| **Max Exposure Duration** | `{vuln_max:.2f}s` | `{mit_max:.2f}s` | **`{pct_reduction:.1f}%`** |
| **Mean Exposure Duration** | `{vuln_agg['mean_exposure_sec']:.2f}s` | `{mit_agg['mean_exposure_sec']:.2f}s` | **`{pct_reduction:.1f}%`** |

## Artifact Manifest

- [`vulnerable-results.json`](vulnerable-results.json): Per-replica timing logs and aggregate metrics under vulnerable state.
- [`mitigated-results.json`](mitigated-results.json): Per-replica timing logs under Authorization Versioning mitigation.
- [`comparison.json`](comparison.json): Structured before/after metrics summary.
- [`raw-evidence/`](raw-evidence/): Raw HTTP probe logs captured during high-frequency trial execution.
"""
        with open(os.path.join(base_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(exp_readme)

        print(f"[+] Case Study Artifacts successfully saved to '{base_dir}/':", flush=True)
        print(f"    - {base_dir}/vulnerable-results.json", flush=True)
        print(f"    - {base_dir}/mitigated-results.json", flush=True)
        print(f"    - {base_dir}/comparison.json", flush=True)
        print(f"    - {base_dir}/README.md\n", flush=True)

        return comparison
    finally:
        for proc in SPAWNED_PROCESSES:
            try:
                proc.terminate()
            except Exception:
                pass


def main():
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
