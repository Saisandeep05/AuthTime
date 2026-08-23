# Standalone Reproduction Script for AuthTime Finding: FIND-EXP-MAIN-1787482146-3
# Target: http://127.0.0.1:8000
# Fault Type: stale_cache
# Generated: 2026-08-23T16:19:13.678407

import httpx
import time

TARGET_URL = "http://127.0.0.1:8000"
EXP_ID = "EXP-MAIN-1787482146-3"

def run_poc():
    print(f"[+] Starting AuthTime Multi-Probe Boundary PoC Execution for {EXP_ID}...")
    client = httpx.Client(timeout=10.0)
    
    # 1. Reset target authorization state
    res_reset = client.post(f"{TARGET_URL}/faults/reset", headers={"X-AuthTime-Request-ID": f"poc-reset-{EXP_ID}", "X-AuthTime-Experiment-ID": EXP_ID})
    res_reset.raise_for_status()

    # 2. Login as target user
    resp = client.post(f"{TARGET_URL}/auth/login", json={"user_id": "admin1"})
    resp.raise_for_status()
    token = resp.json()["access_token"]
    
    headers = {
        "Authorization": f"Bearer {token}",
        "X-AuthTime-Request-ID": f"poc-baseline-{EXP_ID}",
        "X-AuthTime-Experiment-ID": EXP_ID,
    }

    # 3. Verify baseline access
    r_base = client.get(f"{TARGET_URL}/admin/users", headers=headers)
    print(f"[*] Baseline Access Status: {r_base.status_code} (Expected: 200)")
    if r_base.status_code != 200:
        raise RuntimeError(f"Baseline authorization failed with status {r_base.status_code}")

    # 4. Inject controlled fault
    print(f"[*] Injecting Fault: stale_cache...")
    t_start = time.monotonic()
    r_fault = client.post(
        f"{TARGET_URL}/faults/inject",
        json={"fault_type": "stale_cache", "user_id": "admin1", "new_role": "User", "experiment_id": EXP_ID},
        headers={"X-AuthTime-Request-ID": f"poc-fault-{EXP_ID}", "X-AuthTime-Experiment-ID": EXP_ID}
    )
    r_fault.raise_for_status()

    # 5. Multi-probe boundary verification
    probe_offsets = [0.1, max(1.0, 6.00 * 0.5), 6.00, 6.00]
    sorted_offsets = sorted(list(set(probe_offsets)))
    
    for idx, offset in enumerate(sorted_offsets):
        elapsed = time.monotonic() - t_start
        if offset > elapsed:
            time.sleep(offset - elapsed)
        
        probe_headers = dict(headers)
        probe_headers["X-AuthTime-Request-ID"] = f"poc-probe-{EXP_ID}-{idx+1}"
        r_probe = client.get(f"{TARGET_URL}/admin/users", headers=probe_headers)
        
        status_label = "VULNERABLE (200 ALLOW)" if r_probe.status_code == 200 else f"BLOCKED ({r_probe.status_code})"
        print(f"  [+] Probe {idx+1} at offset {offset:.2f}s -> {status_label}")


if __name__ == "__main__":
    run_poc()
