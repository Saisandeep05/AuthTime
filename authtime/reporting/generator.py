"""
Report Generator, Response Sanitizer, and Standalone PoC Script Engine.
"""

import json
import math
import os
import re
from typing import Dict, Any, Optional, List
from datetime import datetime
from authtime.models.schemas import ExperimentResult, SecurityFinding


def compute_severity_score(
    estimated_exposure_sec: float,
    resource_path: str,
    confidence: str,
) -> tuple[float, str]:
    """
    Computes transparent severity score (0.0 to 10.0) based on formula in docs/severity-scoring.md:
    Severity Score = min(10.0, S_exposure * W_endpoint * C_confidence)
    """
    if estimated_exposure_sec <= 0:
        return 0.0, "LOW"

    s_exposure = 3.0 + 2.5 * math.log10(estimated_exposure_sec + 1.0)
    w_endpoint = 1.5 if resource_path.startswith("/admin") else 1.0
    c_conf = 1.0 if confidence == "High" else (0.85 if confidence == "Likely" else 0.70)

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


def sanitize_response_snippet(snippet: Optional[str], enabled: bool = False) -> Optional[str]:
    """
    Sanitizes response snippets:
    - Disabled by default.
    - If enabled, strips credentials, secrets, tokens, and truncates to 200 chars.
    """
    if not enabled or not snippet:
        return None

    # Redact sensitive values
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
            stats_section = f"""
## Aggregate Trial Statistics (N={stats.get('repetitions', 1)})
{rep_note}
- **Minimum Exposure**: `{stats.get('min_sec', 0.0):.2f}s`
- **Maximum Exposure**: `{stats.get('max_sec', 0.0):.2f}s`
- **Mean Exposure (µ)**: `{stats.get('mean_sec', 0.0):.2f}s`
- **Median Exposure (x̃)**: `{stats.get('median_sec', 0.0):.2f}s`
- **Standard Deviation (σ)**: `{stats.get('stddev_sec', 0.0):.2f}s`
- **95th Percentile (P95)**: `{stats.get('p95_sec', 0.0):.2f}s`
"""

        jitter_warn_str = f"\n> ⚠️ **Jitter Warning**: {metrics.jitter_warning}\n" if metrics.jitter_warning else ""

        md = f"""# AuthTime Security Verification Report: {finding.finding_id}

## Executive Summary
- **Finding Title**: {finding.title}
- **Fault Type**: `{finding.fault_type}`
- **Severity Score**: `{finding.severity_score:.1f} / 10.0` (**{finding.severity_label}**)
- **Root Cause**: `{finding.root_cause}` (Confidence: **{finding.root_cause_confidence}**)
- **Baseline Verification**: `{'PASSED' if result.baseline_passed else 'FAILED'}`

---

## Exposure Window Metrics
- **Revocation Timestamp (t_fault)**: `{metrics.fault_timestamp_monotonic:.3f}s`
- **First Unauthorized Access (t_first_unauth)**: `{metrics.first_unauth_monotonic or 0.0:.3f}s`
- **Last Unauthorized Access (t_last_unauth)**: `{metrics.last_unauth_monotonic or 0.0:.3f}s`
- **First Blocked Access (t_first_block)**: `{metrics.first_blocked_monotonic or 0.0:.3f}s`
- **Exposure Interval**: `[{metrics.exposure_interval_min_sec:.2f}s, {metrics.exposure_interval_max_sec:.2f}s]`
- **Estimated Exposure**: `{metrics.estimated_exposure_sec:.2f}s`
- **Measurement Precision (±)**: `{metrics.precision_sec:.2f}s`
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
Standalone reproduction script generated at: [`{finding.poc_script_path}`]({finding.poc_script_path})
"""
        return md

    @staticmethod
    def generate_json_report(result: ExperimentResult, stats: Optional[Dict[str, Any]] = None) -> str:
        data = result.model_dump(mode="json")
        if stats:
            data["aggregated_statistics"] = stats
        return json.dumps(data, indent=2)

    @staticmethod
    def generate_poc_script(result: ExperimentResult, output_dir: str = "reports/poc") -> str:
        """
        Generates a standalone, runnable Python PoC script reproducing the observed unauthorized access.
        """
        os.makedirs(output_dir, exist_ok=True)
        finding = result.finding
        filepath = os.path.join(output_dir, f"{result.experiment_id}_poc.py")

        target_url = result.config.get("target_url", "http://127.0.0.1:8000")
        fault_type = result.config.get("fault_type", "stale_cache")

        script_code = f"""# Standalone Reproduction Script for AuthTime Finding: {finding.finding_id}
# Target: {target_url}
# Fault Type: {fault_type}
# Generated: {datetime.now().isoformat()}

import httpx
import time

TARGET_URL = "{target_url}"

def run_poc():
    print("[+] Starting AuthTime PoC Execution...")

    # 1. Reset target to baseline
    httpx.post(f"{{TARGET_URL}}/faults/reset", headers={{"X-AuthTime-Request-ID": "poc-reset"}})

    # 2. Login as admin user
    resp = httpx.post(f"{{TARGET_URL}}/auth/login", json={{"user_id": "admin1"}})
    token = resp.json()["access_token"]
    headers = {{"Authorization": f"Bearer {{token}}", "X-AuthTime-Request-ID": "poc-probe"}}

    # 3. Verify baseline access
    r_base = httpx.get(f"{{TARGET_URL}}/admin/users", headers=headers)
    print(f"[*] Baseline Access Status: {{r_base.status_code}} (Expected: 200)")

    # 4. Inject Revocation Fault
    print(f"[*] Injecting Fault: {fault_type}...")
    httpx.post(
        f"{{TARGET_URL}}/faults/inject",
        json={{"fault_type": "{fault_type}", "user_id": "admin1", "new_role": "User"}},
        headers={{"X-AuthTime-Request-ID": "poc-fault"}}
    )

    # 5. Immediate Post-Revocation Unauthorized Request Test
    time.sleep(0.1)
    r_post = httpx.get(f"{{TARGET_URL}}/admin/users", headers=headers)
    print(f"[!] Post-Revocation Access Status: {{r_post.status_code}}")

    if r_post.status_code == 200:
        print("[VULNERABLE] Unauthorized access permitted after authorization should have been revoked!")
    else:
        print("[SECURE] Access reliably blocked.")

if __name__ == "__main__":
    run_poc()
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(script_code)

        return filepath
