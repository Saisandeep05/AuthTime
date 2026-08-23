# Standalone Reproduction Script for AuthTime Finding: FIND-EXP-MAIN-1787487553-3
# Target: http://127.0.0.1:8000
# Fault Type: stale_cache
# Protocol Version: 1.0
# Generated: 2026-08-23T17:49:19.630759

import sys
import json
import time
import socket
import ipaddress
import argparse
from urllib.parse import urlparse
import httpx

TARGET_URL = "http://127.0.0.1:8000"
EXP_ID = "EXP-MAIN-1787487553-3"
PROTOCOL_VERSION = "1.0"
PROBE_OFFSETS = [0.0, 0.1, 0.5, 3.0, 6.0]

# Exit Code Contract
EXIT_NO_VIOLATION = 0
EXIT_VIOLATION_DETECTED = 1
EXIT_TARGET_UNAVAILABLE = 2
EXIT_INVALID_TARGET = 3
EXIT_EXPERIMENT_FAILURE = 4


def validate_loopback_safety(url: str):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    if hostname not in ("127.0.0.1", "localhost", "::1"):
        print(f"[!] SAFETY ERROR: Target hostname '{hostname}' is non-local loopback!")
        sys.exit(EXIT_INVALID_TARGET)
    
    try:
        resolved_ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(resolved_ip)
        if not ip_obj.is_loopback:
            print(f"[!] SAFETY ERROR: Target IP '{resolved_ip}' is not a local loopback IP!")
            sys.exit(EXIT_INVALID_TARGET)
    except Exception as e:
        print(f"[!] SAFETY ERROR: Failed to resolve hostname '{hostname}': {e}")
        sys.exit(EXIT_INVALID_TARGET)


def evaluate_http_decision(status_code: int, response_body: str = "") -> str:
    if status_code in (401, 403):
        return "DENY"
    if status_code != 200:
        return "ERROR"
    if response_body:
        try:
            body_json = json.loads(response_body) if isinstance(response_body, str) else response_body
            if isinstance(body_json, dict):
                err_msg = str(body_json.get("error", "") or body_json.get("detail", "") or "").lower()
                if "unauthorized" in err_msg or "denied" in err_msg or "forbidden" in err_msg or "permission" in err_msg:
                    return "DENY"
        except Exception:
            pass
    return "ALLOW"


def evaluate_authorization_violation(actual_dec: str, expected_dec: str, status_code: int, body: str) -> bool:
    effective = evaluate_http_decision(status_code, body) if actual_dec == "ALLOW" else actual_dec
    return (expected_dec.upper() == "DENY" and effective == "ALLOW")


def run_poc(json_output: bool = False) -> int:
    validate_loopback_safety(TARGET_URL)
    
    if not json_output:
        print(f"[+] Starting AuthTime PoC Execution for {EXP_ID}...")
    
    probes_summary = []
    has_violation = False

    try:
        with httpx.Client(timeout=5.0, follow_redirects=False, trust_env=False) as client:
            # 1. Target Identity Handshake
            try:
                r_id = client.get(f"{TARGET_URL}/target/identity")
                if r_id.status_code != 200 or "authtime" not in str(r_id.json().get("target", "")).lower():
                    if not json_output:
                        print(f"[!] ERROR: Target at {TARGET_URL} failed AuthTime identity handshake.")
                    return EXIT_INVALID_TARGET
            except Exception as e:
                if not json_output:
                    print(f"[!] ERROR: Unable to reach target identity endpoint: {e}")
                return EXIT_TARGET_UNAVAILABLE

            # 2. State Reset
            res_reset = client.post(
                f"{TARGET_URL}/faults/reset",
                headers={"X-AuthTime-Request-ID": f"poc-reset-{EXP_ID}", "X-AuthTime-Experiment-ID": EXP_ID}
            )
            res_reset.raise_for_status()

            # 3. Login
            resp = client.post(f"{TARGET_URL}/auth/login", json={"user_id": "admin1"})
            resp.raise_for_status()
            token = resp.json()["access_token"]
            
            headers = {
                "Authorization": f"Bearer {token}",
                "X-AuthTime-Request-ID": f"poc-baseline-{EXP_ID}",
                "X-AuthTime-Experiment-ID": EXP_ID,
                "X-AuthTime-Trial-ID": f"{EXP_ID}-poc-trial",
            }

            # 4. Baseline Verification
            r_base = client.get(f"{TARGET_URL}/admin/users", headers=headers)
            if r_base.status_code != 200:
                if not json_output:
                    print(f"[!] ERROR: Baseline check failed with status {r_base.status_code}")
                return EXIT_EXPERIMENT_FAILURE

            # 5. Fault Injection
            if not json_output:
                print(f"[*] Injecting Fault: stale_cache...")
            t_start = time.monotonic()
            r_fault = client.post(
                f"{TARGET_URL}/faults/inject",
                json={"fault_type": "stale_cache", "user_id": "admin1", "new_role": "User", "experiment_id": EXP_ID},
                headers={"X-AuthTime-Request-ID": f"poc-fault-{EXP_ID}", "X-AuthTime-Experiment-ID": EXP_ID}
            )
            r_fault.raise_for_status()

            # 6. Multi-probe schedule execution
            for idx, offset in enumerate(PROBE_OFFSETS):
                elapsed = time.monotonic() - t_start
                if offset > elapsed:
                    time.sleep(offset - elapsed)
                
                probe_headers = dict(headers)
                probe_headers["X-AuthTime-Request-ID"] = f"poc-probe-{EXP_ID}-{idx+1}"
                
                try:
                    r_probe = client.get(f"{TARGET_URL}/admin/users", headers=probe_headers)
                    st_code = r_probe.status_code
                    body_text = r_probe.text
                except Exception:
                    st_code = 500
                    body_text = ""

                act_dec = evaluate_http_decision(st_code, body_text)
                is_viol = evaluate_authorization_violation(act_dec, "DENY", st_code, body_text)
                
                if is_viol:
                    has_violation = True

                status_str = f"VULNERABLE ({st_code} ALLOW)" if is_viol else f"BLOCKED ({st_code} {act_dec})"
                probes_summary.append({"offset_sec": offset, "status_code": st_code, "actual_decision": act_dec, "is_violation": is_viol})

                if not json_output:
                    print(f"  [+] Probe {idx+1} at offset {offset:.2f}s -> {status_str}")

    except Exception as e:
        if not json_output:
            print(f"[!] UNHANDLED ERROR: {e}")
        return EXIT_EXPERIMENT_FAILURE

    if json_output:
        print(json.dumps({"experiment_id": EXP_ID, "target_url": TARGET_URL, "has_violation": has_violation, "probes": probes_summary}, indent=2))

    return EXIT_VIOLATION_DETECTED if has_violation else EXIT_NO_VIOLATION


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Standalone AuthTime Reproduction PoC")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON results")
    args = parser.parse_args()
    
    code = run_poc(json_output=args.json)
    sys.exit(code)
