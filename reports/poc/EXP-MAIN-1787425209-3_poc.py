# Standalone Reproduction Script for AuthTime Finding: FIND-EXP-MAIN-1787425209-3
# Target: http://127.0.0.1:8000
# Fault Type: stale_cache
# Generated: 2026-08-23T00:30:16.302506

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

    print(f"[*] Injecting Fault: stale_cache...")
    httpx.post(
        f"{TARGET_URL}/faults/inject",
        json={"fault_type": "stale_cache", "user_id": "admin1", "new_role": "User"},
        headers={"X-AuthTime-Request-ID": "poc-fault"}
    )

    time.sleep(0.1)
    r_post = httpx.get(f"{TARGET_URL}/admin/users", headers=headers)
    print(f"[!] Post-Revocation Access Status: {r_post.status_code}")

    if r_post.status_code == 200:
        print("[VULNERABLE] Unauthorized access permitted after authorization should have been revoked!")
    else:
        print("[SECURE] Access reliably blocked.")

if __name__ == "__main__":
    run_poc()
