"""
Unit tests for AuthTime Pydantic data schemas.
"""

from datetime import datetime, timezone
from authtime.models.schemas import (
    RoleEnum,
    GroundTruthState,
    ProbeResult,
    EvidenceEvent,
    ExposureMetric,
    SecurityFinding,
    ExperimentResult,
)


def test_ground_truth_schema():
    gt = GroundTruthState(
        timestamp_monotonic=100.0,
        user_id="user123",
        expected_role=RoleEnum.ADMIN,
        expected_permissions=["READ_INVOICE", "WRITE_INVOICE"],
        resource_path="/admin/users",
        expected_decision="ALLOW",
    )
    assert gt.user_id == "user123"
    assert gt.expected_role == RoleEnum.ADMIN
    assert gt.expected_decision == "ALLOW"


def test_probe_result_schema():
    probe = ProbeResult(
        request_id="req-1",
        experiment_id="exp-1",
        scenario_id="scen-1",
        probe_index=0,
        offset_target=0.0,
        monotonic_timestamp=100.5,
        utc_timestamp=datetime.now(timezone.utc),
        http_status=200,
        actual_decision="ALLOW",
        ground_truth_decision="DENY",
        is_violation=True,
        response_latency_ms=12.5,
    )
    assert probe.is_violation is True
    assert probe.response_body_snippet is None


def test_security_finding_schema():
    finding = SecurityFinding(
        finding_id="FIND-1",
        title="Stale Cache Revocation Exposure",
        fault_type="stale_cache",
        severity_score=7.8,
        severity_label="HIGH",
        config_snapshot={"jwt_ttl": 300, "cache_ttl": 60},
        time_scale_enabled=False,
        time_scale_factor=1.0,
        observed_exposure=ExposureMetric(
            fault_timestamp_monotonic=100.0,
            first_unauth_monotonic=100.1,
            last_unauth_monotonic=147.2,
            first_blocked_monotonic=160.1,
            exposure_interval_min_sec=47.2,
            exposure_interval_max_sec=60.1,
            estimated_exposure_sec=53.65,
            precision_sec=6.45,
            scheduler_jitter_ms=2.1,
            unauthorized_request_count=11,
            total_probes_fired=15,
        ),
        root_cause="AUTHORIZATION_CACHE",
        root_cause_confidence="Likely",
        explanation="Stale cache retained permissions post-revocation.",
        real_world_calibration="Matches 60s reverse proxy session cache default.",
        reproduction_curl="curl http://127.0.0.1:8000/admin/users",
        poc_script_path="reports/poc/FIND-1_poc.py",
    )
    assert finding.severity_score == 7.8
    assert finding.severity_label == "HIGH"
