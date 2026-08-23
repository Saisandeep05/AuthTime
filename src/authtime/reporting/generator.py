"""
Report Generator, Response Sanitizer, and Standalone PoC Script Engine.
"""

import html
import json
import math
import os
import re
from typing import Dict, Any, Optional, List
from datetime import datetime
from authtime.models.schemas import ExperimentResult, SecurityFinding, ExposureMetric


def compute_severity_score(
    metrics: Any,
    resource_path: str,
    confidence: str,
) -> tuple[float, str]:
    """
    Computes transparent severity score (0.0 to 10.0) based on formula in docs/severity-scoring.md:
    Severity Score = min(10.0, S_exposure * W_endpoint * C_confidence)
    For right-censored metrics, uses lower_bound exposure.
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
    w_endpoint = 1.5 if resource_path.startswith("/admin") else 1.0
    c_conf = 1.0 if "PROVEN" in confidence else (0.85 if "SUPPORTED" in confidence else 0.70)

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
        first_blocked_str = f"`{metrics.first_blocked_monotonic:.3f}s`" if metrics.first_blocked_monotonic is not None else "`NOT OBSERVED`"
        interval_str = (
            f"`[{metrics.exposure_interval_min_sec:.2f}s, {metrics.exposure_interval_max_sec:.2f}s]`"
            if metrics.exposure_interval_max_sec is not None
            else f"`[{metrics.exposure_interval_min_sec:.2f}s, ∞] (RIGHT-CENSORED at horizon {metrics.observation_horizon_sec:.2f}s)`"
        )
        est_exp_str = f"`{metrics.estimated_exposure_sec:.2f}s`" if metrics.estimated_exposure_sec is not None else f"`≥ {metrics.exposure_interval_min_sec:.2f}s (Censored)`"
        precision_str = f"`±{metrics.precision_sec:.2f}s`" if metrics.precision_sec is not None else "`UNBOUNDED (Censored Observation)`"

        md = f"""# AuthTime Security Verification Report: {finding.finding_id}

## Executive Summary
- **Finding Title**: {finding.title}
- **Fault Type**: `{finding.fault_type}`
- **Severity Score**: `{finding.severity_score:.1f} / 10.0` (**{finding.severity_label}**)
- **Root Cause**: `{finding.root_cause}` (Confidence: **{finding.root_cause_confidence}**)
- **Measurement Status**: `{metrics.measurement_status}`
- **Baseline Verification**: `{'PASSED' if result.baseline_passed else 'FAILED'}`

---

## Exposure Window Metrics
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
Standalone reproduction script generated at: [`{finding.poc_script_path}`]({finding.poc_script_path})
"""
        return md

    @staticmethod
    def generate_html_report(result: ExperimentResult, stats: Optional[Dict[str, Any]] = None) -> str:
        finding = result.finding
        metrics = result.exposure_metrics

        stats_html = ""
        if stats:
            rep_note = f"<p class='note'><strong>Note:</strong> {stats['limited_sample_note']}</p>" if stats.get("limited_sample_note") else ""
            stats_html = f"""
            <h2>Aggregate Trial Statistics (N={stats.get('repetitions', 1)})</h2>
            {rep_note}
            <ul>
                <li><strong>Minimum Exposure:</strong> <code>{stats.get('min_sec', 0.0):.2f}s</code></li>
                <li><strong>Maximum Exposure:</strong> <code>{stats.get('max_sec', 0.0):.2f}s</code></li>
                <li><strong>Mean Exposure (µ):</strong> <code>{stats.get('mean_sec', 0.0):.2f}s</code></li>
                <li><strong>Median Exposure (x̃):</strong> <code>{stats.get('median_sec', 0.0):.2f}s</code></li>
                <li><strong>Standard Deviation (σ):</strong> <code>{stats.get('stddev_sec', 0.0):.2f}s</code></li>
                <li><strong>95th Percentile (P95):</strong> <code>{stats.get('p95_sec', 0.0):.2f}s</code></li>
            </ul>
            """

        jitter_warn_html = f"<div class='warning'><strong>⚠️ Jitter Warning:</strong> {metrics.jitter_warning}</div>" if metrics.jitter_warning else ""
        badge_class = finding.severity_label.lower()
        first_blocked_str = f"{metrics.first_blocked_monotonic:.3f}s" if metrics.first_blocked_monotonic is not None else "NOT OBSERVED"
        interval_str = (
            f"[{metrics.exposure_interval_min_sec:.2f}s, {metrics.exposure_interval_max_sec:.2f}s]"
            if metrics.exposure_interval_max_sec is not None
            else f"[{metrics.exposure_interval_min_sec:.2f}s, ∞] (RIGHT-CENSORED)"
        )
        est_exp_str = f"{metrics.estimated_exposure_sec:.2f}s" if metrics.estimated_exposure_sec is not None else f"≥ {metrics.exposure_interval_min_sec:.2f}s (Censored)"
        precision_str = f"±{metrics.precision_sec:.2f}s" if metrics.precision_sec is not None else "UNBOUNDED"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuthTime Security Verification Report - {finding.finding_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1a1a1a; max-width: 900px; margin: 0 auto; padding: 2rem 1rem; background-color: #f8f9fa; }}
        .card {{ background: #ffffff; border-radius: 8px; padding: 2rem; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05); margin-bottom: 1.5rem; border: 1px solid #e9ecef; }}
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
            <tr><th>Finding Title</th><td>{finding.title}</td></tr>
            <tr><th>Fault Type</th><td><code>{finding.fault_type}</code></td></tr>
            <tr><th>Severity Score</th><td><code>{finding.severity_score:.1f} / 10.0</code> <span class="badge {badge_class}">{finding.severity_label}</span></td></tr>
            <tr><th>Root Cause</th><td><code>{finding.root_cause}</code> (Confidence: <strong>{finding.root_cause_confidence}</strong>)</td></tr>
            <tr><th>Measurement Status</th><td><code>{metrics.measurement_status}</code></td></tr>
            <tr><th>Baseline Status</th><td><strong>{'PASSED' if result.baseline_passed else 'FAILED'}</strong></td></tr>
        </table>
    </div>

    <div class="card">
        <h2>Exposure Window Metrics</h2>
        <table>
            <tr><th>Revocation Timestamp (t_fault)</th><td><code>{metrics.fault_timestamp_monotonic:.3f}s</code></td></tr>
            <tr><th>First Unauthorized Access (t_first_unauth)</th><td><code>{metrics.first_unauth_monotonic or 0.0:.3f}s</code></td></tr>
            <tr><th>Last Unauthorized Access (t_last_unauth)</th><td><code>{metrics.last_unauth_monotonic or 0.0:.3f}s</code></td></tr>
            <tr><th>First Blocked Access (t_first_block)</th><td><code>{first_blocked_str}</code></td></tr>
            <tr><th>Exposure Interval</th><td><code>{interval_str}</code></td></tr>
            <tr><th>Estimated Exposure Window</th><td><strong><code>{est_exp_str}</code></strong></td></tr>
            <tr><th>Measurement Precision</th><td><code>{precision_str}</code></td></tr>
            <tr><th>Scheduler Jitter</th><td><code>{metrics.scheduler_jitter_ms:.2f}ms</code></td></tr>
        </table>
        {jitter_warn_html}
        {stats_html}
    </div>

    <div class="card">
        <h2>Root Cause Analysis & Real-World Calibration</h2>
        <p>{finding.explanation}</p>
        <h3>Real-World Calibration</h3>
        <p>{finding.real_world_calibration}</p>
    </div>

    <div class="card">
        <h2>Reproduction & PoC Script</h2>
        <pre><code>{finding.reproduction_curl}</code></pre>
        <p>Standalone Python PoC: <code>{finding.poc_script_path}</code></p>
    </div>
</body>
</html>
"""
        return html

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
        metrics = result.exposure_metrics
        exp_min = metrics.exposure_interval_min_sec
        exp_max = metrics.exposure_interval_max_sec or metrics.observation_horizon_sec

        script_code = f"""# Standalone Reproduction Script for AuthTime Finding: {finding.finding_id}
# Target: {target_url}
# Fault Type: {fault_type}
# Generated: {datetime.now().isoformat()}

import httpx
import time

TARGET_URL = "{target_url}"

def run_poc():
    print("[+] Starting AuthTime Multi-Probe Boundary PoC Execution...")
    httpx.post(f"{{TARGET_URL}}/faults/reset", headers={{"X-AuthTime-Request-ID": "poc-reset"}})
    resp = httpx.post(f"{{TARGET_URL}}/auth/login", json={{"user_id": "admin1"}})
    token = resp.json()["access_token"]
    headers = {{"Authorization": f"Bearer {{token}}", "X-AuthTime-Request-ID": "poc-probe"}}

    r_base = httpx.get(f"{{TARGET_URL}}/admin/users", headers=headers)
    print(f"[*] Baseline Access Status: {{r_base.status_code}} (Expected: 200)")
    if r_base.status_code != 200:
        raise RuntimeError("Baseline authorization failed!")

    print(f"[*] Injecting Fault: {fault_type}...")
    t_start = time.monotonic()
    r_fault = httpx.post(
        f"{{TARGET_URL}}/faults/inject",
        json={{"fault_type": "{fault_type}", "user_id": "admin1", "new_role": "User"}},
        headers={{"X-AuthTime-Request-ID": "poc-fault"}}
    )
    if r_fault.status_code != 200:
        raise RuntimeError("Fault injection failed on target!")

    probe_offsets = [0.1, max(1.0, {exp_min:.2f} * 0.5), {exp_min:.2f}, {exp_max:.2f}]
    for offset in sorted(list(set(probe_offsets))):
        elapsed = time.monotonic() - t_start
        if offset > elapsed:
            time.sleep(offset - elapsed)
        
        r_probe = httpx.get(f"{{TARGET_URL}}/admin/users", headers=headers)
        status = "VULNERABLE (200 ALLOW)" if r_probe.status_code == 200 else f"BLOCKED ({{r_probe.status_code}})"
        print(f"  [+] Probe at offset {{offset:.2f}}s -> {{status}}")


if __name__ == "__main__":
    run_poc()
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(script_code)

        return filepath
