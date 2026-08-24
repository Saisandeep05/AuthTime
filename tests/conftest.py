"""
Shared pytest fixtures and factory functions for AuthTime test suite.
Provides reusable factories for ProbeResult, ExposureMetric, SecurityFinding,
and ExperimentResult to eliminate test data duplication across test modules.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

import pytest

from authtime.models.schemas import (
    ProbeResult,
    ExposureMetric,
    SecurityFinding,
    ExperimentResult,
    EvidenceEvent,
    DecisionType,
    GroundTruthDecision,
    MeasurementStatus,
    SeverityLabel,
    ConfidenceLevel,
)


@pytest.fixture
def probe_result_factory():
    """Factory for creating ProbeResult instances with sensible defaults."""

    def _create(
        *,
        probe_index: int = 0,
        monotonic_timestamp: float = 100.0,
        http_status: int = 200,
        actual_decision: DecisionType = "ALLOW",
        ground_truth_decision: GroundTruthDecision = "DENY",
        is_violation: bool = True,
        response_latency_ms: float = 2.0,
        experiment_id: str = "exp-test",
        scenario_id: str = "scen-test",
        offset_target: float = 0.0,
    ) -> ProbeResult:
        return ProbeResult(
            request_id=f"req-{uuid.uuid4().hex[:8]}",
            experiment_id=experiment_id,
            scenario_id=scenario_id,
            probe_index=probe_index,
            offset_target=offset_target,
            monotonic_timestamp=monotonic_timestamp,
            utc_timestamp=datetime.now(timezone.utc),
            http_status=http_status,
            actual_decision=actual_decision,
            ground_truth_decision=ground_truth_decision,
            is_violation=is_violation,
            response_latency_ms=response_latency_ms,
        )

    return _create


@pytest.fixture
def exposure_metric_factory():
    """Factory for creating ExposureMetric instances with configurable censoring state."""

    def _create(
        *,
        fault_timestamp_monotonic: float = 100.0,
        exposure_interval_min_sec: float = 5.0,
        exposure_interval_max_sec: Optional[float] = 10.0,
        estimated_exposure_sec: Optional[float] = 7.5,
        precision_sec: Optional[float] = 2.5,
        scheduler_jitter_ms: float = 1.0,
        unauthorized_request_count: int = 3,
        total_probes_fired: int = 10,
        is_censored: bool = False,
        measurement_status: MeasurementStatus = "OBSERVED_TRANSITION",
    ) -> ExposureMetric:
        return ExposureMetric(
            fault_timestamp_monotonic=fault_timestamp_monotonic,
            exposure_interval_min_sec=exposure_interval_min_sec,
            exposure_interval_max_sec=exposure_interval_max_sec,
            estimated_exposure_sec=estimated_exposure_sec,
            precision_sec=precision_sec,
            scheduler_jitter_ms=scheduler_jitter_ms,
            unauthorized_request_count=unauthorized_request_count,
            total_probes_fired=total_probes_fired,
            is_censored=is_censored,
            measurement_status=measurement_status,
        )

    return _create


@pytest.fixture
def experiment_result_factory(exposure_metric_factory):
    """Factory for creating valid ExperimentResult instances for aggregation tests."""

    def _create(
        *,
        experiment_id: str = "exp-agg-test",
        baseline_passed: bool = True,
        cleanup_status: str = "VERIFIED",
        exposure_interval_min_sec: float = 5.0,
        exposure_interval_max_sec: Optional[float] = 10.0,
        estimated_exposure_sec: Optional[float] = 7.5,
        is_censored: bool = False,
        measurement_status: MeasurementStatus = "OBSERVED_TRANSITION",
        severity_score: float = 6.0,
        severity_label: SeverityLabel = "MEDIUM",
    ) -> ExperimentResult:
        metrics = exposure_metric_factory(
            exposure_interval_min_sec=exposure_interval_min_sec,
            exposure_interval_max_sec=exposure_interval_max_sec,
            estimated_exposure_sec=estimated_exposure_sec,
            is_censored=is_censored,
            measurement_status=measurement_status,
        )
        finding = SecurityFinding(
            finding_id=f"FIND-{experiment_id}",
            title="Test Finding",
            fault_type="stale_cache",
            severity_score=severity_score,
            severity_label=severity_label,
            config_snapshot={"target_url": "http://testclient", "fault_type": "stale_cache"},
            time_scale_enabled=True,
            time_scale_factor=0.01,
            observed_exposure=metrics,
            root_cause="AUTHORIZATION_CACHE",
            root_cause_confidence="SUPPORTED",
            explanation="Test explanation.",
            real_world_calibration="Test calibration.",
            reproduction_curl="curl http://testclient/admin/users",
            poc_script_path="reports/poc/test_poc.py",
        )
        return ExperimentResult(
            experiment_id=experiment_id,
            run_id=f"RUN-{uuid.uuid4().hex[:8]}",
            created_at_utc=datetime.now(timezone.utc),
            config={"target_url": "http://testclient", "fault_type": "stale_cache"},
            baseline_passed=baseline_passed,
            cleanup_status=cleanup_status,
            probes=[],
            events=[],
            exposure_metrics=metrics,
            finding=finding,
            summary_stats={"trial_count": 1},
        )

    return _create
