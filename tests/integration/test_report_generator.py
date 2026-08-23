"""
Integration tests for ReportGenerator & Standalone PoC Generator.
"""

import os
from datetime import datetime, timezone
from authtime.models.schemas import (
    ExperimentResult,
    ExposureMetric,
    SecurityFinding,
)
from authtime.reporting.generator import ReportGenerator, sanitize_response_snippet


def test_response_snippet_sanitization():
    raw_snippet = '{"access_token": "secret_jwt_token_12345", "Bearer": "Bearer secret_jwt_token_12345"}'
    sanitized = sanitize_response_snippet(raw_snippet, enabled=True)
    assert "[REDACTED]" in sanitized
    assert "secret_jwt_token_12345" not in sanitized

    disabled_snippet = sanitize_response_snippet(raw_snippet, enabled=False)
    assert disabled_snippet is None


def test_report_generation(tmp_path):
    metric = ExposureMetric(
        fault_timestamp_monotonic=10.0,
        first_unauth_monotonic=10.1,
        last_unauth_monotonic=16.0,
        first_blocked_monotonic=16.1,
        exposure_interval_min_sec=6.0,
        exposure_interval_max_sec=6.1,
        estimated_exposure_sec=6.05,
        precision_sec=0.05,
        scheduler_jitter_ms=1.5,
        unauthorized_request_count=5,
        total_probes_fired=10,
    )
    finding = SecurityFinding(
        finding_id="FIND-TEST-1",
        title="Authorization Exposure Finding: AUTHORIZATION_CACHE",
        fault_type="stale_cache",
        severity_score=6.5,
        severity_label="MEDIUM",
        config_snapshot={"cache_ttl": 60.0},
        time_scale_enabled=False,
        time_scale_factor=1.0,
        observed_exposure=metric,
        root_cause="AUTHORIZATION_CACHE",
        root_cause_confidence="Likely",
        explanation="Stale cache test explanation.",
        real_world_calibration="Tested cache_ttl=60s.",
        reproduction_curl="curl http://127.0.0.1:8000/admin/users",
        poc_script_path="reports/poc/test_poc.py",
    )
    result = ExperimentResult(
        experiment_id="exp-test-rep",
        created_at_utc=datetime.now(timezone.utc),
        config={"target_url": "http://127.0.0.1:8000"},
        baseline_passed=True,
        probes=[],
        events=[],
        exposure_metrics=metric,
        finding=finding,
        summary_stats={},
    )

    md = ReportGenerator.generate_markdown_report(result)
    assert "FIND-TEST-1" in md
    assert "MEDIUM" in md

    html = ReportGenerator.generate_html_report(result)
    assert "<!DOCTYPE html>" in html
    assert "FIND-TEST-1" in html

    poc_file = ReportGenerator.generate_poc_script(result, str(tmp_path))
    assert os.path.exists(poc_file)
    with open(poc_file, "r") as f:
        code = f.read()
        assert "run_poc" in code
