# Standalone Reproduction Script for AuthTime Finding: FIND-EXP-MAIN-1787431866-3
# Target: http://127.0.0.1:8000
# Fault Type: stale_cache
# Generated: 2026-08-23T02:21:12.530489

import httpx
import time

TARGET_URL = "http://127.0.0.1:8000"

def run_poc():
    print("[+] Starting AuthTime PoC Execution...")
    httpx.post(f"{TARGET_URL}/faults/reset", headers={"X-AuthTime-Request-ID": "poc-reset"})
    resp = httpx.post(f"{TARGET_URL}/auth/login", json={"user_id": "admin1"})
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}", "X-AuthTime-Request-ID": "poc-probe"}

    r_base = httpx.get(f"{TARGET_URL}/admin/users", headers=headers)
    print(f"[*] Baseline Access Status: {r_base.status_code} (Expected: 200)")
    if r_base.status_code != 200:
        raise RuntimeError("Baseline authorization failed!")

    print(f"[*] Injecting Fault: stale_cache...")
    r_fault = httpx.post(
        f"{TARGET_URL}/faults/inject",
        json={"fault_type": "stale_cache", "user_id": "admin1", "new_role": "User"},
        headers={"X-AuthTime-Request-ID": "poc-fault"}
    )
    if r_fault.status_code != 200:
        raise RuntimeError("Fault injection failed on target!")

    sleep_time = min(0.1, 6.00) if 6.00 > 0 else 0.1
    time.sleep(sleep_time)
    r_post = httpx.get(f"{TARGET_URL}/admin/users", headers=headers)
    print(f"[!] Post-Revocation Access Status (at {sleep_time:.2f}s): {r_post.status_code}")

    if r_post.status_code == 200:
        print("[VULNERABLE] Unauthorized access permitted after authorization should have been revoked!")
    else:
        print("[SECURE] Access reliably blocked.")

if __name__ == "__main__":
    run_poc()
