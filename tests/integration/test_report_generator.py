"""
Integration tests for ReportGenerator and PoC Artifact Engine.
"""

import os
import json
import pytest
from datetime import datetime, timezone

from authtime.models.schemas import (
    ExperimentResult,
    ProbeResult,
    ExposureMetric,
    SecurityFinding,
)
from authtime.reporting.generator import ReportGenerator, sanitize_response_snippet


def test_response_sanitization():
    raw = '{"token": "Bearer secret-token-12345", "access_token": "secret-value"}'
    # Disabled by default
    assert sanitize_response_snippet(raw, enabled=False) is None

    # Enabled: should redact tokens and secrets
    cleaned = sanitize_response_snippet(raw, enabled=True)
    assert "secret-token-12345" not in cleaned
    assert "secret-value" not in cleaned
    assert "[REDACTED]" in cleaned


def test_markdown_and_json_report_generation(tmp_path):
    metrics = ExposureMetric(
        fault_timestamp_monotonic=100.0,
        first_unauth_monotonic=100.1,
        last_unauth_monotonic=147.2,
        first_blocked_monotonic=160.1,
        exposure_interval_min_sec=47.2,
        exposure_interval_max_sec=60.1,
        estimated_exposure_sec=53.65,
        precision_sec=6.45,
        scheduler_jitter_ms=1.5,
        unauthorized_request_count=2,
        total_probes_fired=5,
    )

    finding = SecurityFinding(
        finding_id="FIND-EXP-001",
        title="Authorization Exposure Finding: AUTHORIZATION_CACHE",
        fault_type="stale_cache",
        severity_score=8.4,
        severity_label="HIGH",
        config_snapshot={"cache_ttl_seconds": 60.0},
        time_scale_enabled=False,
        time_scale_factor=1.0,
        observed_exposure=metrics,
        root_cause="AUTHORIZATION_CACHE",
        root_cause_confidence="Likely",
        explanation="Stale cache entry allowed access.",
        real_world_calibration="Mirrors Redis cache defaults.",
        reproduction_curl="curl http://127.0.0.1:8000/admin/users",
        poc_script_path="reports/poc/EXP-001_poc.py",
    )

    result = ExperimentResult(
        experiment_id="EXP-001",
        created_at_utc=datetime.now(timezone.utc),
        config={"target_url": "http://127.0.0.1:8000", "fault_type": "stale_cache"},
        baseline_passed=True,
        probes=[],
        events=[],
        exposure_metrics=metrics,
        finding=finding,
        summary_stats={"trial_count": 1},
    )

    stats = {
        "repetitions": 3,
        "min_sec": 45.0,
        "max_sec": 55.0,
        "mean_sec": 50.0,
        "median_sec": 50.0,
        "stddev_sec": 5.0,
        "p95_sec": 54.5,
        "limited_sample_note": "If N < 5, the report must explicitly identify the result as a limited-sample observation.",
    }

    md_report = ReportGenerator.generate_markdown_report(result, stats)
    assert "AuthTime Security Verification Report" in md_report
    assert "FIND-EXP-001" in md_report
    assert "Aggregate Trial Statistics (N=3)" in md_report
    assert "limited-sample observation" in md_report

    json_report = ReportGenerator.generate_json_report(result, stats)
    parsed = json.loads(json_report)
    assert parsed["experiment_id"] == "EXP-001"
    assert parsed["aggregated_statistics"]["mean_sec"] == 50.0

    poc_path = ReportGenerator.generate_poc_script(result, output_dir=str(tmp_path))
    assert os.path.exists(poc_path)
    with open(poc_path, "r", encoding="utf-8") as f:
        content = f.read()
        assert "run_poc" in content
        assert "stale_cache" in content
