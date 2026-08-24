"""
Report Generator, Response Sanitizer, and Dynamic Standalone PoC Script Engine.
Generates fully dynamic, self-contained PoC scripts with IP-bound loopback transport,
generic scenario parameterization, and thorough post-cleanup authorization state re-verification.
"""

import html
import json
import math
import os
import re
from typing import Dict, Any, Optional, List
from datetime import datetime
from authtime.models.schemas import ExperimentResult, SecurityFinding, ExposureMetric
from authtime.adapters.contract import DEFAULT_ADMIN_USERS_CONTRACT, ResourceContract
from authtime.statistics.censoring import calculate_kaplan_meier_survival, format_uncertainty_interval


def compute_severity_score(
    metrics: Any,
    resource_path: str,
    confidence: str,
) -> tuple[float, str]:
    """
    Computes transparent severity score (0.0 to 10.0) based on formula in docs/severity-scoring.md:
    Severity Score = min(10.0, S_exposure * W_endpoint * C_confidence)
    For right-censored metrics, uses lower_bound exposure and marks estimate as conservative.
    """
    if isinstance(metrics, (int, float)):
        exposure_sec = float(metrics)
    elif hasattr(metrics, "estimated_exposure_sec"):
        exposure_sec = metrics.estimated_exposure_sec if metrics.estimated_exposure_sec is not None else metrics.exposure_interval_min_sec
    else:
        exposure_sec = 0.0

    if exposure_sec <= 0:
        return 0.0, "LOW"

    s_exposure = 3.0 + 2.5 * math.log10(exposure_sec + 1.0)
    
    if resource_path.startswith("/admin") or "admin" in resource_path:
        w_endpoint = 1.5
    elif "secret" in resource_path or "key" in resource_path or "payment" in resource_path:
        w_endpoint = 1.8
    else:
        w_endpoint = 1.0

    conf_str = str(confidence).upper()
    if conf_str == "PROVEN" or conf_str == "CONFIRMED":
        c_conf = 1.0
    elif conf_str == "SUPPORTED":
        c_conf = 0.85
    elif conf_str == "INDICATIVE" or conf_str == "INFERRED":
        c_conf = 0.70
    else:
        c_conf = 0.50

    raw_score = min(10.0, round(s_exposure * w_endpoint * c_conf, 1))

    if raw_score >= 9.0:
        label = "CRITICAL"
    elif raw_score >= 7.0:
        label = "HIGH"
    elif raw_score >= 4.0:
        label = "MEDIUM"
    else:
        label = "LOW"

    return raw_score, label


def sanitize_response_snippet(snippet: Optional[str], enabled: bool = True) -> Optional[str]:
    if not enabled or not snippet:
        return None

    cleaned = re.sub(r"(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*", r"\1[REDACTED_TOKEN]", snippet, flags=re.IGNORECASE)
    cleaned = re.sub(r"\"(access_token|secret|password|key)\":\s*\"[^\"]+\"", r'"\1": "[REDACTED]"', cleaned, flags=re.IGNORECASE)

    if len(cleaned) > 200:
        cleaned = cleaned[:197] + "..."

    return cleaned


class ReportGenerator:
    @staticmethod
    def generate_markdown_report(result: ExperimentResult, stats: Optional[Dict[str, Any]] = None) -> str:
        finding = result.finding
        metrics = result.exposure_metrics

        stats_section = ""
        if stats:
            rep_note = f"\n> **Note**: {stats['limited_sample_note']}\n" if stats.get("limited_sample_note") else ""
            mean_str = f"`{stats['mean_exposure_sec']:.2f}s`" if stats.get("mean_exposure_sec") is not None else "`NOT ESTIMABLE (Right-Censored Data Present)`"
            stats_section = f"""
## Aggregate Trial Statistics (N={stats.get('trial_count', 1)})
{rep_note}
- **Minimum Exposure**: `{stats.get('min_exposure_sec', 0.0):.2f}s`
- **Maximum Exposure**: `{stats.get('max_exposure_sec', 0.0):.2f}s`
- **Mean Exposure (µ)**: {mean_str}
- **Median Exposure (x̃)**: `{stats.get('median_sec', 0.0):.2f}s`
"""

        jitter_warn_str = f"\n> ⚠️ **Jitter Warning**: {metrics.jitter_warning}\n" if metrics.jitter_warning else ""
        first_blocked_str = f"`{metrics.first_blocked_monotonic:.3f}s`" if metrics.first_blocked_monotonic is not None else "`NOT OBSERVED`"
        interval_str = (
            f"`[{metrics.exposure_interval_min_sec:.2f}s, {metrics.exposure_interval_max_sec:.2f}s]`"
            if metrics.exposure_interval_max_sec is not None
            else f"`[{metrics.exposure_interval_min_sec:.2f}s, ∞] (RIGHT-CENSORED at horizon {metrics.observation_horizon_sec:.2f}s)`"
        )
        est_exp_str = f"`{metrics.estimated_exposure_sec:.2f}s`" if metrics.estimated_exposure_sec is not None else f"`≥ {metrics.exposure_interval_min_sec:.2f}s (Conservative Lower Bound)`"
        precision_str = f"`±{metrics.precision_sec:.2f}s`" if metrics.precision_sec is not None else "`UNBOUNDED (Censored Observation)`"

        poc_link = finding.poc_script_path
        if poc_link.startswith("reports/poc/"):
            poc_link = "../poc/" + os.path.basename(poc_link)

        md = f"""# AuthTime Security Verification Report: {finding.finding_id}

## Executive Summary
- **Protocol Version**: `{result.protocol_version}`
- **Schema Version**: `{result.schema_version}`
- **Run Identifier**: `{result.run_id or 'N/A'}`
- **Finding Title**: {finding.title}
- **Fault Type**: `{finding.fault_type}`
- **Severity Score**: `{finding.severity_score:.1f} / 10.0` (**{finding.severity_label}**)
- **Root Cause**: `{finding.root_cause}` (Confidence: **{finding.root_cause_confidence}**)
- **Measurement Status**: `{metrics.measurement_status}`
- **Baseline Verification**: `{'PASSED' if result.baseline_passed else 'FAILED'}`
- **Cleanup Verification**: `{result.cleanup_status}`

---

## Exposure Window Metrics & Timing Methodology
- **Revocation Timestamp (t_fault)**: `{metrics.fault_timestamp_monotonic:.3f}s`
- **First Unauthorized Access (t_first_unauth)**: `{metrics.first_unauth_monotonic or 0.0:.3f}s`
- **Last Unauthorized Access (t_last_unauth)**: `{metrics.last_unauth_monotonic or 0.0:.3f}s`
- **First Blocked Access (t_first_block)**: {first_blocked_str}
- **Exposure Interval**: {interval_str}
- **Estimated Exposure**: {est_exp_str}
- **Measurement Precision**: {precision_str}
- **Scheduler Jitter**: `{metrics.scheduler_jitter_ms:.2f}ms`
{jitter_warn_str}
{stats_section}

---

## Root Cause Explanation
{finding.explanation}

### Real-World System Calibration
{finding.real_world_calibration}

---

## Reproduction & PoC Script
```bash
{finding.reproduction_curl}
```
Standalone reproduction script generated at: [`{finding.poc_script_path}`]({poc_link})
"""
        return md

    @staticmethod
    def generate_html_report(result: ExperimentResult, stats: Optional[Dict[str, Any]] = None) -> str:
        finding = result.finding
        metrics = result.exposure_metrics

        stats_html = ""
        if stats:
            rep_note = f"<p class='note'><strong>Note:</strong> {html.escape(str(stats['limited_sample_note']))}</p>" if stats.get("limited_sample_note") else ""
            mean_str = f"{stats['mean_exposure_sec']:.2f}s" if stats.get("mean_exposure_sec") is not None else "NOT ESTIMABLE (Right-Censored Data Present)"
            stats_html = f"""
            <h2>Aggregate Trial Statistics (N={stats.get('trial_count', 1)})</h2>
            {rep_note}
            <ul>
                <li><strong>Minimum Exposure:</strong> <code>{stats.get('min_exposure_sec', 0.0):.2f}s</code></li>
                <li><strong>Maximum Exposure:</strong> <code>{stats.get('max_exposure_sec', 0.0):.2f}s</code></li>
                <li><strong>Mean Exposure (µ):</strong> <code>{html.escape(mean_str)}</code></li>
                <li><strong>Median Exposure (x̃):</strong> <code>{stats.get('median_sec', 0.0):.2f}s</code></li>
            </ul>
            """

        badge_class = str(finding.severity_label).lower()
        jitter_warn_html = f"<p class='warning'><strong>Jitter Warning:</strong> {html.escape(str(metrics.jitter_warning))}</p>" if metrics.jitter_warning else ""
        first_blocked_str = f"{metrics.first_blocked_monotonic:.3f}s" if metrics.first_blocked_monotonic is not None else "NOT OBSERVED"
        interval_str = (
            f"[{metrics.exposure_interval_min_sec:.2f}s, {metrics.exposure_interval_max_sec:.2f}s]"
            if metrics.exposure_interval_max_sec is not None
            else f"[{metrics.exposure_interval_min_sec:.2f}s, ∞] (RIGHT-CENSORED at horizon {metrics.observation_horizon_sec:.2f}s)"
        )
        est_exp_str = f"{metrics.estimated_exposure_sec:.2f}s" if metrics.estimated_exposure_sec is not None else f"≥ {metrics.exposure_interval_min_sec:.2f}s (Conservative Lower Bound)"
        precision_str = f"±{metrics.precision_sec:.2f}s" if metrics.precision_sec is not None else "UNBOUNDED (Censored Observation)"

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AuthTime Security Report - {html.escape(finding.finding_id)}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1e293b; max-width: 900px; margin: 2rem auto; padding: 0 1rem; background-color: #f8fafc; }}
        .card {{ background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); margin-bottom: 1.5rem; }}
        h1, h2, h3 {{ color: #0f172a; }}
        .badge {{ display: inline-block; padding: 0.25rem 0.75rem; font-weight: 700; border-radius: 4px; color: white; font-size: 0.9rem; }}
        .badge.critical {{ background-color: #dc2626; }}
        .badge.high {{ background-color: #ea580c; }}
        .badge.medium {{ background-color: #d97706; }}
        .badge.low {{ background-color: #2563eb; }}
        table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
        th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #e2e8f0; }}
        th {{ background-color: #f1f5f9; }}
        pre {{ background-color: #0f172a; color: #f8fafc; padding: 1rem; border-radius: 6px; overflow-x: auto; }}
        code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>AuthTime Security Verification Report</h1>
        <h2>Executive Summary</h2>
        <table>
            <tr><th>Protocol Version</th><td><code>{html.escape(result.protocol_version)}</code></td></tr>
            <tr><th>Run Identifier</th><td><code>{html.escape(result.run_id or 'N/A')}</code></td></tr>
            <tr><th>Finding Title</th><td>{html.escape(finding.title)}</td></tr>
            <tr><th>Fault Type</th><td><code>{html.escape(finding.fault_type)}</code></td></tr>
            <tr><th>Severity Score</th><td><code>{finding.severity_score:.1f} / 10.0</code> <span class="badge {badge_class}">{html.escape(finding.severity_label)}</span></td></tr>
            <tr><th>Root Cause</th><td><code>{html.escape(finding.root_cause)}</code> (Confidence: <strong>{html.escape(str(finding.root_cause_confidence))}</strong>)</td></tr>
            <tr><th>Measurement Status</th><td><code>{html.escape(metrics.measurement_status)}</code></td></tr>
            <tr><th>Baseline Status</th><td><strong>{'PASSED' if result.baseline_passed else 'FAILED'}</strong></td></tr>
            <tr><th>Cleanup Status</th><td><strong>{html.escape(result.cleanup_status)}</strong></td></tr>
        </table>
    </div>

    <div class="card">
        <h2>Exposure Window Metrics</h2>
        <table>
            <tr><th>Revocation Timestamp (t_fault)</th><td><code>{metrics.fault_timestamp_monotonic:.3f}s</code></td></tr>
            <tr><th>First Unauthorized Access (t_first_unauth)</th><td><code>{metrics.first_unauth_monotonic or 0.0:.3f}s</code></td></tr>
            <tr><th>Last Unauthorized Access (t_last_unauth)</th><td><code>{metrics.last_unauth_monotonic or 0.0:.3f}s</code></td></tr>
            <tr><th>First Blocked Access (t_first_block)</th><td><code>{html.escape(first_blocked_str)}</code></td></tr>
            <tr><th>Exposure Interval</th><td><code>{html.escape(interval_str)}</code></td></tr>
            <tr><th>Estimated Exposure Window</th><td><strong><code>{html.escape(est_exp_str)}</code></strong></td></tr>
            <tr><th>Measurement Precision</th><td><code>{html.escape(precision_str)}</code></td></tr>
            <tr><th>Scheduler Jitter</th><td><code>{metrics.scheduler_jitter_ms:.2f}ms</code></td></tr>
        </table>
        {jitter_warn_html}
        {stats_html}
    </div>

    <div class="card">
        <h2>Root Cause Analysis & Real-World Calibration</h2>
        <p>{html.escape(finding.explanation)}</p>
        <h3>Real-World Calibration</h3>
        <p>{html.escape(finding.real_world_calibration)}</p>
    </div>

    <div class="card">
        <h2>Reproduction & PoC Script</h2>
        <pre><code>{html.escape(finding.reproduction_curl)}</code></pre>
        <p>Standalone Python PoC: <code>{html.escape(finding.poc_script_path)}</code></p>
    </div>
</body>
</html>
"""
        return html_doc

    @staticmethod
    def generate_json_report(result: ExperimentResult, stats: Optional[Dict[str, Any]] = None) -> str:
        data = result.model_dump(mode="json")
        if stats:
            data["aggregated_statistics"] = stats
        return json.dumps(data, indent=2)

    @staticmethod
    def generate_poc_script(result: ExperimentResult, output_dir: str = "reports/poc") -> str:
        os.makedirs(output_dir, exist_ok=True)
        finding = result.finding
        filepath = os.path.join(output_dir, f"{result.experiment_id}_poc.py")

        target_url = result.config.get("target_url", "http://127.0.0.1:8000")
        fault_type = result.config.get("fault_type", "stale_cache")
        target_user = result.config.get("target_user_id", "admin1")
        resource_path = result.config.get("resource_path", "/admin/users")

        if result.exact_probe_schedule:
            probe_offsets = [item["requested_offset_sec"] if isinstance(item, dict) else item for item in result.exact_probe_schedule]
        else:
            offsets = [p.offset_target for p in result.probes]
            probe_offsets = offsets if offsets else [0.0, 0.1, 0.5, 3.0, 6.0]

        contract_json = json.dumps(DEFAULT_ADMIN_USERS_CONTRACT.model_dump(), indent=2)

        script_code = f"""# Dynamic Standalone Reproduction Script for AuthTime Finding: {finding.finding_id}
# Target URL: {target_url}
# Fault Type: {fault_type}
# Target User: {target_user}
# Resource Path: {resource_path}
# Protocol Version: {result.protocol_version}
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

TARGET_URL = "{target_url}"
EXP_ID = "{result.experiment_id}"
PROTOCOL_VERSION = "{result.protocol_version}"
TARGET_USER = "{target_user}"
RESOURCE_PATH = "{resource_path}"
FAULT_TYPE = "{fault_type}"
PROBE_OFFSETS = {probe_offsets}
RESOURCE_CONTRACT = {contract_json}

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
        return False, None, f"URL parse error: {{e}}"

    if parsed.scheme not in ("http", "https"):
        return False, None, f"Invalid scheme '{{parsed.scheme}}'. Only 'http' and 'https' are allowed."

    if parsed.username or parsed.password:
        return False, None, "Embedded credentials in URL are prohibited."

    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not hostname or hostname not in ("127.0.0.1", "localhost", "::1"):
        return False, None, f"SAFETY VIOLATION: Hostname '{{hostname}}' is non-local loopback!"

    try:
        addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addr_info:
            return False, None, f"DNS resolution returned no addresses for hostname '{{hostname}}'"

        bound_ip = None
        for family, socktype, proto, canonname, sockaddr in addr_info:
            ip_str = sockaddr[0]
            ip_obj = ipaddress.ip_address(ip_str)
            if not ip_obj.is_loopback:
                return False, None, f"SAFETY VIOLATION: Resolved IP '{{ip_str}}' is not loopback!"
            if not bound_ip:
                bound_ip = f"[{{ip_str}}]" if ":" in ip_str else ip_str

        bound_url = f"{{parsed.scheme}}://{{bound_ip}}:{{port}}"
        return True, bound_url, ""
    except Exception as e:
        return False, None, f"DNS resolution failure for '{{hostname}}': {{e}}"


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
            print(f"[!] SAFETY ERROR: {{err}}")
        return EXIT_INVALID_TARGET

    poc_run_id = f"RUN-POC-{{uuid.uuid4()}}"
    
    if not json_output:
        print(f"[+] Starting AuthTime PoC Execution for {{EXP_ID}} (Run ID: {{poc_run_id}})...")
    
    probes_summary = []
    has_violation = False
    cleanup_success = False

    try:
        with httpx.Client(base_url=bound_url, headers={{"Host": "127.0.0.1"}}, timeout=5.0, follow_redirects=False, trust_env=False) as client:
            try:
                # 1. Complete Target Identity Handshake Verification
                try:
                    r_id = client.get("/target/identity")
                    if r_id.status_code != 200:
                        if not json_output:
                            print(f"[!] ERROR: Target returned status {{r_id.status_code}} on identity endpoint.")
                        return EXIT_INVALID_TARGET
                    id_data = r_id.json() if r_id.text else {{}}
                    if (
                        id_data.get("product") != "AuthTime"
                        or id_data.get("protocol_version") != PROTOCOL_VERSION
                        or "reference-target" not in str(id_data.get("target_type", ""))
                        or not isinstance(id_data.get("capabilities"), list)
                    ):
                        if not json_output:
                            print(f"[!] ERROR: Target identity verification failed: {{id_data}}")
                        return EXIT_INVALID_TARGET
                except Exception as e:
                    if not json_output:
                        print(f"[!] ERROR: Unable to reach target identity endpoint: {{e}}")
                    return EXIT_TARGET_UNAVAILABLE

                # 2. Target Reset
                res_reset = client.post(
                    "/faults/reset",
                    headers={{"X-AuthTime-Request-ID": f"poc-reset-{{poc_run_id}}", "X-AuthTime-Experiment-ID": EXP_ID}}
                )
                res_reset.raise_for_status()

                # 3. Login
                resp = client.post("/auth/login", json={{"user_id": TARGET_USER}})
                resp.raise_for_status()
                token = resp.json()["access_token"]
                
                headers = {{
                    "Authorization": f"Bearer {{token}}",
                    "X-AuthTime-Request-ID": f"poc-baseline-{{poc_run_id}}",
                    "X-AuthTime-Experiment-ID": EXP_ID,
                    "X-AuthTime-Run-ID": poc_run_id,
                }}

                # 4. Baseline Authorized Access Verification
                r_base = client.get(RESOURCE_PATH, headers=headers)
                base_dec = evaluate_contract_response(r_base.status_code, r_base.text, RESOURCE_CONTRACT)
                if base_dec != "ALLOW":
                    if not json_output:
                        print(f"[!] ERROR: Baseline check failed with decision '{{base_dec}}' (status {{r_base.status_code}})")
                    return EXIT_EXPERIMENT_FAILURE

                # 5. Fault Injection
                if not json_output:
                    print(f"[*] Injecting Fault: {{FAULT_TYPE}}...")
                t_start = time.monotonic()
                r_fault = client.post(
                    "/faults/inject",
                    json={{"fault_type": FAULT_TYPE, "user_id": TARGET_USER, "new_role": "User", "experiment_id": EXP_ID}},
                    headers={{"X-AuthTime-Request-ID": f"poc-fault-{{poc_run_id}}", "X-AuthTime-Experiment-ID": EXP_ID}}
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
                    probe_headers["X-AuthTime-Request-ID"] = f"poc-probe-{{poc_run_id}}-{{idx+1}}"
                    
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

                    status_str = f"VULNERABLE ({{st_code}} ALLOW)" if is_viol else f"BLOCKED ({{st_code}} {{act_dec}})"
                    probes_summary.append({{
                        "probe_index": idx + 1,
                        "requested_offset_sec": offset,
                        "actual_offset_sec": actual_offset_sec,
                        "timing_error_sec": timing_error_sec,
                        "raw_http_status": st_code,
                        "error_category": error_cat,
                        "actual_decision": act_dec,
                        "is_violation": is_viol,
                    }})

                    if not json_output:
                        print(f"  [+] Probe {{idx+1}} at requested {{offset:.2f}}s (actual {{actual_offset_sec:.2f}}s, error {{timing_error_sec:.3f}}s) -> {{status_str}}")

            finally:
                # 7. Guaranteed Post-Reset State & Authorization Re-Verification
                try:
                    res_c = client.post(
                        "/faults/reset",
                        headers={{"X-AuthTime-Request-ID": f"poc-cleanup-{{poc_run_id}}", "X-AuthTime-Experiment-ID": EXP_ID}}
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
                        print(f"[!] CLEANUP ERROR: Target state reset failed: {{e}}")
                    cleanup_success = False

    except Exception as e:
        if not json_output:
            print(f"[!] UNHANDLED ERROR: {{e}}")
        return EXIT_EXPERIMENT_FAILURE

    if not cleanup_success:
        if not json_output:
            print(f"[!] CRITICAL: Post-reset authorization cleanup verification failed! Target state not verified clean.")
        return EXIT_CLEANUP_FAILURE

    if json_output:
        print(json.dumps({{
            "experiment_id": EXP_ID,
            "run_id": poc_run_id,
            "target_url": TARGET_URL,
            "has_violation": has_violation,
            "cleanup_success": cleanup_success,
            "probes": probes_summary
        }}, indent=2))

    return EXIT_VIOLATION_DETECTED if has_violation else EXIT_NO_VIOLATION


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Standalone AuthTime Reproduction PoC")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON results")
    args = parser.parse_args()
    
    code = run_poc(json_output=args.json)
    sys.exit(code)
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(script_code)

        return filepath
