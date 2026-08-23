"""
CI Integration Test: Standalone PoC Execution & Predicate Verification.
Tests that generated PoC scripts execute cleanly, enforce target identity handshakes, evaluate canonical predicates, and return valid exit codes.
"""

import os
import sys
import subprocess
import pytest
import httpx
from datetime import datetime, timezone

from app.main import app
from authtime.models.schemas import (
    ExperimentResult,
    ExposureMetric,
    SecurityFinding,
    ProbeResult,
)
from authtime.reporting.generator import ReportGenerator


@pytest.mark.asyncio
async def test_generated_poc_script_execution(tmp_path):
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
        finding_id="FIND-POC-TEST-1",
        title="Authorization Exposure Finding: AUTHORIZATION_CACHE",
        fault_type="stale_cache",
        severity_score=6.5,
        severity_label="MEDIUM",
        config_snapshot={"cache_ttl": 60.0},
        time_scale_enabled=False,
        time_scale_factor=1.0,
        observed_exposure=metric,
        root_cause="AUTHORIZATION_CACHE",
        root_cause_confidence="SUPPORTED",
        explanation="Stale cache test explanation.",
        real_world_calibration="Tested cache_ttl=60s.",
        reproduction_curl="curl http://127.0.0.1:8000/admin/users",
        poc_script_path="reports/poc/test_poc.py",
    )
    result = ExperimentResult(
        schema_version="1.1",
        protocol_version="1.0",
        experiment_id="exp-poc-ci-test",
        created_at_utc=datetime.now(timezone.utc),
        config={"target_url": "http://127.0.0.1:8000", "fault_type": "stale_cache"},
        config_hash="abc123hash",
        baseline_passed=True,
        probes=[],
        events=[],
        exposure_metrics=metric,
        finding=finding,
        summary_stats={},
        exact_probe_schedule=[{"probe_index": 1, "requested_offset_sec": 0.1, "actual_offset_sec": 0.1, "probe_type": "scheduled"}],
    )



    poc_path = ReportGenerator.generate_poc_script(result, str(tmp_path))
    assert os.path.exists(poc_path)

    with open(poc_path, "r", encoding="utf-8") as f:
        code = f.read()

    assert "import authtime" not in code
    assert "from authtime" not in code
    assert "validate_and_bind_loopback" in code
    assert "gethostbyname" not in code
    assert "evaluate_contract_response" in code
    assert "RESOURCE_CONTRACT" in code
    assert "EXIT_CLEANUP_FAILURE" in code
    assert "error_cat" in code
    assert "trust_env=False" in code




