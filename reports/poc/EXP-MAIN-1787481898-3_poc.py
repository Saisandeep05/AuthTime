# Standalone Reproduction Script for AuthTime Finding: FIND-EXP-MAIN-1787481898-3
# Target: http://127.0.0.1:8000
# Fault Type: stale_cache
# Generated: 2026-08-23T16:15:05.209551

import httpx
import time

TARGET_URL = "http://127.0.0.1:8000"

def run_poc():
    print("[+] Starting AuthTime Multi-Probe Boundary PoC Execution...")
    httpx.post(f"{TARGET_URL}/faults/reset", headers={"X-AuthTime-Request-ID": "poc-reset"})
    resp = httpx.post(f"{TARGET_URL}/auth/login", json={"user_id": "admin1"})
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}", "X-AuthTime-Request-ID": "poc-probe"}

    r_base = httpx.get(f"{TARGET_URL}/admin/users", headers=headers)
    print(f"[*] Baseline Access Status: {r_base.status_code} (Expected: 200)")
    if r_base.status_code != 200:
        raise RuntimeError("Baseline authorization failed!")

    print(f"[*] Injecting Fault: stale_cache...")
    t_start = time.monotonic()
    r_fault = httpx.post(
        f"{TARGET_URL}/faults/inject",
        json={"fault_type": "stale_cache", "user_id": "admin1", "new_role": "User"},
        headers={"X-AuthTime-Request-ID": "poc-fault"}
    )
    if r_fault.status_code != 200:
        raise RuntimeError("Fault injection failed on target!")

    probe_offsets = [0.1, max(1.0, 6.00 * 0.5), 6.00, 6.00]
    for offset in sorted(list(set(probe_offsets))):
        elapsed = time.monotonic() - t_start
        if offset > elapsed:
            time.sleep(offset - elapsed)
        
        r_probe = httpx.get(f"{TARGET_URL}/admin/users", headers=headers)
        status = "VULNERABLE (200 ALLOW)" if r_probe.status_code == 200 else f"BLOCKED ({r_probe.status_code})"
        print(f"  [+] Probe at offset {offset:.2f}s -> {status}")


if __name__ == "__main__":
    run_poc()
