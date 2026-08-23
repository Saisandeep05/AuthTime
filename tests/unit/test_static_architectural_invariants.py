"""
CI Static Architectural Invariants & Anti-Pattern Regression Test Suite.
Enforces that legacy heuristics, gethostbyname, fabricated HTTP status codes, and swallowed exceptions
can NEVER be reintroduced into the codebase or generated artifact templates.
"""

import os
import re
import glob
import pytest


def get_all_src_python_files():
    src_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "src")
    py_files = []
    for root, _, files in os.walk(src_dir):
        for f in files:
            if f.endswith(".py"):
                py_files.append(os.path.join(root, f))
    return py_files


def test_no_gethostbyname_in_codebase():
    py_files = get_all_src_python_files()
    for filepath in py_files:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        assert "gethostbyname" not in content, f"Banned function 'gethostbyname' found in {filepath}"


def test_no_heuristic_field_matches_in_codebase():
    py_files = get_all_src_python_files()
    banned_patterns = [
        r"\"data\"\s+in\s+body",
        r"\"users\"\s+in\s+body_json.*return\s+[\"']ALLOW[\"']",
        r"\"access_token\"\s+in\s+body_json.*return\s+[\"']ALLOW[\"']",
    ]

    for filepath in py_files:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        for pattern in banned_patterns:
            assert not re.search(pattern, content, re.IGNORECASE), (
                f"Banned heuristic pattern '{pattern}' found in {filepath}"
            )


def test_no_fabricated_http_status_codes_for_transport_errors():
    py_files = get_all_src_python_files()
    banned_assigns = [
        r"st_code\s*=\s*408",
        r"st_code\s*=\s*502",
        r"st_code\s*=\s*500",
    ]

    for filepath in py_files:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        for pattern in banned_assigns:
            assert not re.search(pattern, content), (
                f"Banned fabricated status code assignment '{pattern}' found in {filepath}"
            )


def test_no_swallowed_cleanup_exceptions():
    py_files = get_all_src_python_files()
    for filepath in py_files:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        if "reset" in content.lower() or "cleanup" in content.lower():
            assert "except Exception:\n        pass" not in content, (
                f"Swallowed exception 'except Exception: pass' found in {filepath}"
            )
            assert "except Exception:\n            pass" not in content, (
                f"Swallowed exception 'except Exception: pass' found in {filepath}"
            )


def test_generated_poc_is_truly_standalone_with_zero_authtime_imports(tmp_path):
    from authtime.reporting.generator import ReportGenerator
    from authtime.models.schemas import ExperimentResult, SecurityFinding, ExposureMetric
    from datetime import datetime, timezone

    metric = ExposureMetric(
        fault_timestamp_monotonic=10.0,
        exposure_interval_min_sec=6.0,
        exposure_interval_max_sec=6.1,
        estimated_exposure_sec=6.05,
        precision_sec=0.05,
        scheduler_jitter_ms=1.5,
        unauthorized_request_count=5,
        total_probes_fired=10,
    )
    finding = SecurityFinding(
        finding_id="FIND-STANDALONE-TEST",
        title="Test Finding",
        fault_type="stale_cache",
        severity_score=6.5,
        severity_label="MEDIUM",
        config_snapshot={"cache_ttl": 60.0},
        time_scale_enabled=False,
        time_scale_factor=1.0,
        observed_exposure=metric,
        root_cause="AUTHORIZATION_CACHE",
        root_cause_confidence="SUPPORTED",
        explanation="Test explanation",
        real_world_calibration="N/A",
        reproduction_curl="curl http://127.0.0.1:8000/admin/users",
        poc_script_path="reports/poc/test_poc.py",
    )
    result = ExperimentResult(
        schema_version="1.1",
        protocol_version="1.0",
        experiment_id="exp-standalone-test",
        created_at_utc=datetime.now(timezone.utc),
        config={"target_url": "http://127.0.0.1:8000", "fault_type": "stale_cache"},
        baseline_passed=True,
        probes=[],
        events=[],
        exposure_metrics=metric,
        finding=finding,
        summary_stats={},
    )

    poc_path = ReportGenerator.generate_poc_script(result, str(tmp_path))
    with open(poc_path, "r", encoding="utf-8") as f:
        code = f.read()

    assert "import authtime" not in code, "Standalone PoC script contains prohibited 'import authtime'"
    assert "from authtime" not in code, "Standalone PoC script contains prohibited 'from authtime'"
    assert "gethostbyname" not in code
    assert "validate_and_bind_loopback" in code
    assert "EXIT_CLEANUP_FAILURE" in code


