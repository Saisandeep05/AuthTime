"""
Unit tests for AuthTime Pydantic schemas and invariant validators.
"""

import pytest
from pydantic import ValidationError
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


def test_temporal_invariant_validation():
    with pytest.raises(ValidationError):
        ExposureMetric(
            fault_timestamp_monotonic=10.0,
            exposure_interval_min_sec=10.0,
            exposure_interval_max_sec=5.0,  # Min > Max invariant violation
            scheduler_jitter_ms=1.0,
            unauthorized_request_count=1,
            total_probes_fired=1,
        )


def test_invalid_literal_type_validation():
    with pytest.raises(ValidationError):
        GroundTruthState(
            timestamp_monotonic=100.0,
            user_id="admin1",
            expected_role=RoleEnum.ADMIN,
            expected_permissions=["admin:read"],
            resource_path="/admin/users",
            expected_decision="INVALID_DECISION",  # Must be "ALLOW" or "DENY"
        )
