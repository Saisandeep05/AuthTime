"""
Unit tests for AuthTime Pydantic schemas.
"""

from datetime import datetime, timezone
from authtime.models.schemas import (
    RoleEnum,
    GroundTruthState,
    ProbeResult,
    ExposureMetric,
    SecurityFinding,
    ExperimentResult,
)


def test_schema_instantiation():
    gt = GroundTruthState(
        timestamp_monotonic=100.0,
        user_id="admin1",
        expected_role=RoleEnum.ADMIN,
        expected_permissions=["admin:read"],
        resource_path="/admin/users",
        expected_decision="ALLOW",
    )
    assert gt.user_id == "admin1"
    assert gt.expected_role == RoleEnum.ADMIN

    metric = ExposureMetric(
        fault_timestamp_monotonic=10.0,
        first_unauth_monotonic=10.1,
        last_unauth_monotonic=16.0,
        first_blocked_monotonic=16.1,
        exposure_interval_min_sec=6.0,
        exposure_interval_max_sec=6.1,
        estimated_exposure_sec=6.05,
        precision_sec=0.05,
        scheduler_jitter_ms=2.5,
        unauthorized_request_count=5,
        total_probes_fired=10,
    )
    assert metric.estimated_exposure_sec == 6.05
    assert metric.scheduler_jitter_ms == 2.5
