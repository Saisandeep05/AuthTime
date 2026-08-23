"""
Interactive Live AuthTime Verification Script for Terminal.
"""

import sys
import os
import time
import httpx
import uvicorn
import threading

# Add root directory to sys.path if running from scripts/
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src_dir = os.path.join(root_dir, "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from app.main import app as fastapi_app

TARGET_URL = "http://127.0.0.1:8000"


def ensure_server_running():
    try:
        httpx.get(f"{TARGET_URL}/events", timeout=1.0)
        return
    except Exception:
        pass

    print("[*] Starting local reference target server on http://127.0.0.1:8000...", flush=True)
    config = uvicorn.Config(app=fastapi_app, host="127.0.0.1", port=8000, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    time.sleep(1.5)


def main():
    print("=" * 70, flush=True)
    print(" [AuthTime Interactive Live Verification Test]", flush=True)
    print("=" * 70, flush=True)

    ensure_server_running()

    print("\n[Step 0] Resetting Target Application State to Baseline...", flush=True)
    try:
        httpx.post(f"{TARGET_URL}/faults/reset", headers={"X-AuthTime-Request-ID": "live-reset"})
        print("  [+] Target application state reset complete.", flush=True)
    except Exception as e:
        print(f"  [-] Failed to reset target server: {e}", flush=True)
        return

    print("\n[Step 1] Logging in as Admin ('admin1')...", flush=True)
    resp = httpx.post(f"{TARGET_URL}/auth/login", json={"user_id": "admin1"})
    if resp.status_code != 200:
        print(f"  [-] Login failed ({resp.status_code}).", flush=True)
        return
    token = resp.json()["access_token"]
    print(f"  [+] Login Successful! Access Token: {token[:25]}...", flush=True)

    headers = {"Authorization": f"Bearer {token}", "X-AuthTime-Request-ID": "live-test"}

    print("\n[Step 2] Testing Baseline Access to Protected Resource ('/admin/users')...", flush=True)
    r_base = httpx.get(f"{TARGET_URL}/admin/users", headers=headers)
    print(f"   Status Code: {r_base.status_code}", flush=True)
    print(f"   Response Payload: {r_base.text}", flush=True)
    assert r_base.status_code == 200, f"Baseline check failed! Status: {r_base.status_code}"
    print("  [+] Baseline verified! Admin access is allowed.", flush=True)

    print("\n[Step 3] Revoking Admin Authorization via Fault Injection ('stale_cache', TTL=10s)...", flush=True)
    httpx.post(
        f"{TARGET_URL}/faults/inject",
        json={"fault_type": "stale_cache", "user_id": "admin1", "new_role": "User", "cache_ttl_seconds": 10.0},
        headers={"X-AuthTime-Request-ID": "live-fault"},
    )
    print("  [+] Authorization revoked in Database! Stale cache set to 10 seconds.", flush=True)

    print("\n[Step 4] Requesting Protected Resource IMMEDIATELY Post-Revocation...", flush=True)
    r_post = httpx.get(f"{TARGET_URL}/admin/users", headers=headers)
    print(f"   Post-Revocation Status Code: {r_post.status_code}", flush=True)
    if r_post.status_code == 200:
        print("   [!] VULNERABLE! Unauthorized access allowed because authorization cache is stale.", flush=True)
    else:
        print("   [+] SECURE! Access was blocked.", flush=True)

    print("\n[Step 5] Waiting 10 Seconds for Authorization Cache TTL to Expire...", flush=True)
    for remaining in range(10, 0, -1):
        print(f"   Waiting... {remaining}s remaining", end="\r", flush=True)
        time.sleep(1.0)
    print("   Cache TTL expired!                             ", flush=True)

    print("\n[Step 6] Requesting Protected Resource AFTER Cache TTL Expiry...", flush=True)
    r_expired = httpx.get(f"{TARGET_URL}/admin/users", headers=headers)
    print(f"   Post-Expiry Status Code: {r_expired.status_code}", flush=True)
    print(f"   Response Payload: {r_expired.text}", flush=True)

    if r_expired.status_code in (401, 403):
        print("  [+] SUCCESS! Access is now reliably blocked.", flush=True)
    else:
        print("  [-] Still allowed!", flush=True)

    print("\n" + "=" * 70, flush=True)
    print(" Test Complete! AuthTime temporal authorization exposure verified.", flush=True)
    print("=" * 70, flush=True)


if __name__ == "__main__":
    main()
