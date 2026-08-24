# Dynamic Standalone Reproduction Script for AuthTime Finding: FIND-EXP-MAIN-1787592981-3
# Target URL: http://127.0.0.1:8000
# Fault Type: stale_cache
# Target User: admin1
# Resource Path: /admin/users
# Protocol Version: 1.0
# NOTE: Zero external dependencies beyond standard Python 3.8+ library and httpx.

import sys
import json
import time
import uuid
import socket
import ipaddress
import argparse
from urllib.parse import urlparse
import httpx

TARGET_URL = "http://127.0.0.1:8000"
EXP_ID = "EXP-MAIN-1787592981-3"
PROTOCOL_VERSION = "1.0"
TARGET_USER = "admin1"
RESOURCE_PATH = "/admin/users"
FAULT_TYPE = "stale_cache"
PROBE_OFFSETS = [0.0, 0.1, 0.5, 3.0, 6.0]
RESOURCE_CONTRACT = {
  "contract_id": "contract-admin-users-v1",
  "contract_version": "1.0",
  "target_type": "reference-target",
  "resource_path": "/admin/users",
  "accepted_status_codes": [
    200
  ],
  "denial_status_codes": [
    401,
    403
  ],
  "required_json_keys": [
    "users"
  ],
  "denial_json_values": [
    "permission denied",
    "unauthorized",
    "access denied",
    "forbidden",
    "missing token",
    "invalid token"
  ]
}

# Exit Code Contract
EXIT_NO_VIOLATION = 0
EXIT_VIOLATION_DETECTED = 1
EXIT_TARGET_UNAVAILABLE = 2
EXIT_INVALID_TARGET = 3
EXIT_EXPERIMENT_FAILURE = 4
EXIT_CLEANUP_FAILURE = 5


def validate_and_bind_loopback(target_url: str):
    # Validates target URL loopback safety and binds HTTP transport directly to the validated IP.
    if not target_url or not isinstance(target_url, str):
        return False, None, "URL must be a non-empty string"
    try:
        parsed = urlparse(target_url)
    except Exception as e:
        return False, None, f"URL parse error: {e}"

    if parsed.scheme not in ("http", "https"):
        return False, None, f"Invalid scheme '{parsed.scheme}'. Only 'http' and 'https' are allowed."

    if parsed.username or parsed.password:
        return False, None, "Embedded credentials in URL are prohibited."

    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not hostname or hostname not in ("127.0.0.1", "localhost", "::1"):
        return False, None, f"SAFETY VIOLATION: Hostname '{hostname}' is non-local loopback!"

    try:
        addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addr_info:
            return False, None, f"DNS resolution returned no addresses for hostname '{hostname}'"

        bound_ip = None
        for family, socktype, proto, canonname, sockaddr in addr_info:
            ip_str = sockaddr[0]
            ip_obj = ipaddress.ip_address(ip_str)
            if not ip_obj.is_loopback:
                return False, None, f"SAFETY VIOLATION: Resolved IP '{ip_str}' is not loopback!"
            if not bound_ip:
                bound_ip = f"[{ip_str}]" if ":" in ip_str else ip_str

        bound_url = f"{parsed.scheme}://{bound_ip}:{port}"
        return True, bound_url, ""
    except Exception as e:
        return False, None, f"DNS resolution failure for '{hostname}': {e}"


def evaluate_contract_response(status_code: int, response_body: str, contract: dict) -> str:
    if status_code in contract.get("denial_status_codes", [401, 403]):
        return "DENY"
    if status_code in (500, 502, 503, 504):
        return "HTTP_ERROR"
    if status_code not in contract.get("accepted_status_codes", [200]):
        return "UNKNOWN"
    if not response_body:
        return "UNKNOWN"

    try:
        body_json = json.loads(response_body) if isinstance(response_body, str) else response_body
        if isinstance(body_json, dict):
            detail_val = str(body_json.get("detail", "") or body_json.get("error", "") or body_json.get("message", "")).lower()
            for d_val in contract.get("denial_json_values", []):
                if d_val in detail_val:
                    return "DENY"

            for req_key in contract.get("required_json_keys", []):
                val = body_json.get(req_key)
                if isinstance(val, (list, dict)) and len(val) > 0:
                    return "ALLOW"
            return "UNKNOWN"
    except Exception:
        return "UNKNOWN"
    return "UNKNOWN"


def run_poc(json_output: bool = False) -> int:
    is_ok, bound_url, err = validate_and_bind_loopback(TARGET_URL)
    if not is_ok:
        if not json_output:
            print(f"[!] SAFETY ERROR: {err}")
        return EXIT_INVALID_TARGET

    poc_run_id = f"RUN-POC-{uuid.uuid4()}"
    
    if not json_output:
        print(f"[+] Starting AuthTime PoC Execution for {EXP_ID} (Run ID: {poc_run_id})...")
    
    probes_summary = []
    has_violation = False
    cleanup_success = False

    try:
        with httpx.Client(base_url=bound_url, headers={"Host": "127.0.0.1"}, timeout=5.0, follow_redirects=False, trust_env=False) as client:
            try:
                # 1. Complete Target Identity Handshake Verification
                try:
                    r_id = client.get("/target/identity")
                    if r_id.status_code != 200:
                        if not json_output:
                            print(f"[!] ERROR: Target returned status {r_id.status_code} on identity endpoint.")
                        return EXIT_INVALID_TARGET
                    id_data = r_id.json() if r_id.text else {}
                    if (
                        id_data.get("product") != "AuthTime"
                        or id_data.get("protocol_version") != PROTOCOL_VERSION
                        or "reference-target" not in str(id_data.get("target_type", ""))
                        or not isinstance(id_data.get("capabilities"), list)
                    ):
                        if not json_output:
                            print(f"[!] ERROR: Target identity verification failed: {id_data}")
                        return EXIT_INVALID_TARGET
                except Exception as e:
                    if not json_output:
                        print(f"[!] ERROR: Unable to reach target identity endpoint: {e}")
                    return EXIT_TARGET_UNAVAILABLE

                # 2. Target Reset
                res_reset = client.post(
                    "/faults/reset",
                    headers={"X-AuthTime-Request-ID": f"poc-reset-{poc_run_id}", "X-AuthTime-Experiment-ID": EXP_ID}
                )
                res_reset.raise_for_status()

                # 3. Login
                resp = client.post("/auth/login", json={"user_id": TARGET_USER})
                resp.raise_for_status()
                token = resp.json()["access_token"]
                
                headers = {
                    "Authorization": f"Bearer {token}",
                    "X-AuthTime-Request-ID": f"poc-baseline-{poc_run_id}",
                    "X-AuthTime-Experiment-ID": EXP_ID,
                    "X-AuthTime-Run-ID": poc_run_id,
                }

                # 4. Baseline Authorized Access Verification
                r_base = client.get(RESOURCE_PATH, headers=headers)
                base_dec = evaluate_contract_response(r_base.status_code, r_base.text, RESOURCE_CONTRACT)
                if base_dec != "ALLOW":
                    if not json_output:
                        print(f"[!] ERROR: Baseline check failed with decision '{base_dec}' (status {r_base.status_code})")
                    return EXIT_EXPERIMENT_FAILURE

                # 5. Fault Injection
                if not json_output:
                    print(f"[*] Injecting Fault: {FAULT_TYPE}...")
                t_start = time.monotonic()
                r_fault = client.post(
                    "/faults/inject",
                    json={"fault_type": FAULT_TYPE, "user_id": TARGET_USER, "new_role": "User", "experiment_id": EXP_ID},
                    headers={"X-AuthTime-Request-ID": f"poc-fault-{poc_run_id}", "X-AuthTime-Experiment-ID": EXP_ID}
                )
                r_fault.raise_for_status()

                # 6. Probe Schedule Execution
                for idx, offset in enumerate(PROBE_OFFSETS):
                    t_req_start = time.monotonic()
                    elapsed = t_req_start - t_start
                    if offset > elapsed:
                        time.sleep(offset - elapsed)
                    
                    probe_t = time.monotonic()
                    actual_offset_sec = round(probe_t - t_start, 4)
                    timing_error_sec = round(actual_offset_sec - offset, 4)
                    
                    probe_headers = dict(headers)
                    probe_headers["X-AuthTime-Request-ID"] = f"poc-probe-{poc_run_id}-{idx+1}"
                    
                    error_cat = "HTTP_RESPONSE"
                    try:
                        r_probe = client.get(RESOURCE_PATH, headers=probe_headers)
                        st_code = r_probe.status_code
                        body_text = r_probe.text
                    except httpx.TimeoutException:
                        st_code = 0
                        body_text = ""
                        error_cat = "NETWORK_TIMEOUT"
                    except httpx.NetworkError:
                        st_code = 0
                        body_text = ""
                        error_cat = "CONNECTION_ERROR"
                    except Exception as ex_err:
                        st_code = 0
                        body_text = str(ex_err)
                        error_cat = "CLIENT_ERROR"

                    if error_cat == "HTTP_RESPONSE":
                        act_dec = evaluate_contract_response(st_code, body_text, RESOURCE_CONTRACT)
                    else:
                        act_dec = error_cat

                    is_viol = (act_dec == "ALLOW")
                    if is_viol:
                        has_violation = True

                    status_str = f"VULNERABLE ({st_code} ALLOW)" if is_viol else f"BLOCKED ({st_code} {act_dec})"
                    probes_summary.append({
                        "probe_index": idx + 1,
                        "requested_offset_sec": offset,
                        "actual_offset_sec": actual_offset_sec,
                        "timing_error_sec": timing_error_sec,
                        "raw_http_status": st_code,
                        "error_category": error_cat,
                        "actual_decision": act_dec,
                        "is_violation": is_viol,
                    })

                    if not json_output:
                        print(f"  [+] Probe {idx+1} at requested {offset:.2f}s (actual {actual_offset_sec:.2f}s, error {timing_error_sec:.3f}s) -> {status_str}")

            finally:
                # 7. Guaranteed Post-Reset State & Authorization Re-Verification
                try:
                    res_c = client.post(
                        "/faults/reset",
                        headers={"X-AuthTime-Request-ID": f"poc-cleanup-{poc_run_id}", "X-AuthTime-Experiment-ID": EXP_ID}
                    )
                    if res_c.status_code == 200:
                        # Re-verify target identity
                        res_v = client.get("/target/identity")
                        # Re-verify protected endpoint returns 401/403 DENY without valid token
                        res_unauth = client.get(RESOURCE_PATH)
                        if (
                            res_v.status_code == 200
                            and res_v.json().get("product") == "AuthTime"
                            and res_unauth.status_code in (401, 403)
                        ):
                            cleanup_success = True
                except Exception as e:
                    if not json_output:
                        print(f"[!] CLEANUP ERROR: Target state reset failed: {e}")
                    cleanup_success = False

    except Exception as e:
        if not json_output:
            print(f"[!] UNHANDLED ERROR: {e}")
        return EXIT_EXPERIMENT_FAILURE

    if not cleanup_success:
        if not json_output:
            print(f"[!] CRITICAL: Post-reset authorization cleanup verification failed! Target state not verified clean.")
        return EXIT_CLEANUP_FAILURE

    if json_output:
        print(json.dumps({
            "experiment_id": EXP_ID,
            "run_id": poc_run_id,
            "target_url": TARGET_URL,
            "has_violation": has_violation,
            "cleanup_success": cleanup_success,
            "probes": probes_summary
        }, indent=2))

    return EXIT_VIOLATION_DETECTED if has_violation else EXIT_NO_VIOLATION


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Standalone AuthTime Reproduction PoC")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON results")
    args = parser.parse_args()
    
    code = run_poc(json_output=args.json)
    sys.exit(code)
