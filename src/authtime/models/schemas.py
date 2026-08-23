"""
AuthTime Data Models and Pydantic v2 Schemas.
"""

from enum import Enum
from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field, model_validator
from datetime import datetime


class RoleEnum(str, Enum):
    ADMIN = "Admin"
    USER = "User"
    GUEST = "Guest"
    SERVICE_ACCOUNT = "ServiceAccount"


DecisionType = Literal["ALLOW", "DENY", "UNKNOWN"]
GroundTruthDecision = Literal["ALLOW", "DENY", "UNKNOWN", "UNAVAILABLE"]
MeasurementStatus = Literal["OBSERVED_TRANSITION", "CENSORED_LOWER_BOUND", "NO_EXPOSURE", "INVALID_BASELINE", "INCONCLUSIVE", "NON_MONOTONIC"]
SeverityLabel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
ConfidenceLevel = Literal["CONFIRMED", "PROVEN", "SUPPORTED", "INDICATIVE", "INFERRED", "UNDETERMINED"]



class GroundTruthState(BaseModel):
    timestamp_monotonic: float = Field(ge=0.0)
    user_id: str = Field(min_length=1, max_length=128)
    expected_role: RoleEnum
    expected_permissions: List[str]
    resource_path: str
    expected_decision: GroundTruthDecision


class ProbeResult(BaseModel):
    request_id: str
    experiment_id: str
    scenario_id: str
    probe_index: int = Field(ge=0)
    offset_target: float = Field(ge=0.0)
    monotonic_timestamp: float = Field(ge=0.0)
    utc_timestamp: datetime
    http_status: int = Field(ge=0, le=599)
    actual_decision: DecisionType
    ground_truth_decision: GroundTruthDecision
    is_violation: bool
    response_latency_ms: float = Field(ge=0.0)
    node_id: Optional[str] = None
    cache_hit: Optional[bool] = None
    response_body_snippet: Optional[str] = None


class EvidenceEvent(BaseModel):
    event_id: str
    request_id: str
    experiment_id: str
    trial_id: Optional[str] = None
    monotonic_timestamp: float = Field(ge=0.0)
    utc_timestamp: datetime
    event_type: str
    details: Dict[str, Any]


class ExposureMetric(BaseModel):
    fault_timestamp_monotonic: float = Field(ge=0.0)
    first_unauth_monotonic: Optional[float] = Field(None, ge=0.0)
    last_unauth_monotonic: Optional[float] = Field(None, ge=0.0)
    first_blocked_monotonic: Optional[float] = Field(None, ge=0.0)
    exposure_interval_min_sec: float = Field(ge=0.0)
    exposure_interval_max_sec: Optional[float] = Field(None, ge=0.0)
    estimated_exposure_sec: Optional[float] = Field(None, ge=0.0)
    precision_sec: Optional[float] = Field(None, ge=0.0)
    observation_horizon_sec: float = Field(60.0, gt=0.0)
    scheduler_jitter_ms: float = Field(ge=0.0)
    jitter_warning: Optional[str] = None
    unauthorized_request_count: int = Field(ge=0)
    total_probes_fired: int = Field(ge=0)
    is_censored: bool = False
    measurement_status: MeasurementStatus = "OBSERVED_TRANSITION"
    per_replica_exposure: Optional[Dict[str, Any]] = None

    @model_validator(mode="after")
    def validate_temporal_invariants(self) -> "ExposureMetric":
        if self.exposure_interval_max_sec is not None:
            if self.exposure_interval_min_sec > self.exposure_interval_max_sec:
                raise ValueError(
                    f"exposure_interval_min_sec ({self.exposure_interval_min_sec}) cannot exceed "
                    f"exposure_interval_max_sec ({self.exposure_interval_max_sec})"
                )
        if self.first_unauth_monotonic and self.last_unauth_monotonic:
            if self.first_unauth_monotonic > self.last_unauth_monotonic:
                raise ValueError(
                    f"first_unauth_monotonic ({self.first_unauth_monotonic}) cannot succeed "
                    f"last_unauth_monotonic ({self.last_unauth_monotonic})"
                )
        return self


class SecurityFinding(BaseModel):
    finding_id: str
    title: str
    fault_type: str
    severity_score: float = Field(ge=0.0, le=10.0)
    severity_label: SeverityLabel
    config_snapshot: Dict[str, Any]
    time_scale_enabled: bool
    time_scale_factor: float = Field(gt=0.0, le=10.0)
    observed_exposure: ExposureMetric
    root_cause: str
    root_cause_confidence: ConfidenceLevel
    explanation: str
    real_world_calibration: str
    reproduction_curl: str
    poc_script_path: str


class ExperimentResult(BaseModel):
    schema_version: str = "1.1"
    protocol_version: str = "1.0"
    experiment_id: str
    run_id: Optional[str] = None
    created_at_utc: datetime
    config: Dict[str, Any]
    config_hash: Optional[str] = None
    baseline_passed: bool
    cleanup_status: Literal["VERIFIED", "FAILED", "NOT_ATTEMPTED"] = "VERIFIED"
    state_history: Optional[List[str]] = None
    probes: List[ProbeResult]
    events: List[EvidenceEvent]
    raw_observations: Optional[List[Dict[str, Any]]] = None
    exposure_metrics: ExposureMetric
    finding: SecurityFinding
    summary_stats: Dict[str, Any]
    exact_probe_schedule: Optional[List[Dict[str, Any]]] = None
    environment: Optional[Dict[str, Any]] = None




