"""
AuthTime Data Models and Pydantic v2 Schemas.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


class RoleEnum(str, Enum):
    ADMIN = "Admin"
    USER = "User"
    GUEST = "Guest"
    SERVICE_ACCOUNT = "ServiceAccount"


class GroundTruthState(BaseModel):
    timestamp_monotonic: float
    user_id: str
    expected_role: RoleEnum
    expected_permissions: List[str]
    resource_path: str
    expected_decision: str  # "ALLOW" or "DENY"


class ProbeResult(BaseModel):
    request_id: str
    experiment_id: str
    scenario_id: str
    probe_index: int
    offset_target: float
    monotonic_timestamp: float
    utc_timestamp: datetime
    http_status: int
    actual_decision: str  # "ALLOW", "DENY", or "ERROR"

    ground_truth_decision: str  # "ALLOW" or "DENY"
    is_violation: bool
    response_latency_ms: float
    node_id: Optional[str] = None
    cache_hit: Optional[bool] = None
    response_body_snippet: Optional[str] = None


class EvidenceEvent(BaseModel):
    event_id: str
    request_id: str
    experiment_id: str
    monotonic_timestamp: float
    utc_timestamp: datetime
    event_type: str  # "FAULT_INJECTED", "AUTH_CHECK", "CACHE_HIT", "CACHE_EXPIRE"
    details: Dict[str, Any]


class ExposureMetric(BaseModel):
    fault_timestamp_monotonic: float
    first_unauth_monotonic: Optional[float] = None
    last_unauth_monotonic: Optional[float] = None
    first_blocked_monotonic: Optional[float] = None
    exposure_interval_min_sec: float
    exposure_interval_max_sec: Optional[float] = None
    estimated_exposure_sec: Optional[float] = None
    precision_sec: Optional[float] = None
    observation_horizon_sec: float = 60.0
    scheduler_jitter_ms: float
    jitter_warning: Optional[str] = None
    unauthorized_request_count: int
    total_probes_fired: int
    is_censored: bool = False
    measurement_status: str = "OBSERVED_TRANSITION"  # "OBSERVED_TRANSITION", "CENSORED_LOWER_BOUND", "NO_EXPOSURE"





class SecurityFinding(BaseModel):
    finding_id: str
    title: str
    fault_type: str
    severity_score: float = Field(ge=0.0, le=10.0)
    severity_label: str  # LOW, MEDIUM, HIGH, CRITICAL
    config_snapshot: Dict[str, Any]
    time_scale_enabled: bool
    time_scale_factor: float
    observed_exposure: ExposureMetric
    root_cause: str
    root_cause_confidence: str
    explanation: str
    real_world_calibration: str
    reproduction_curl: str
    poc_script_path: str


class ExperimentResult(BaseModel):
    experiment_id: str
    created_at_utc: datetime
    config: Dict[str, Any]
    baseline_passed: bool
    probes: List[ProbeResult]
    events: List[EvidenceEvent]
    exposure_metrics: ExposureMetric
    finding: SecurityFinding
    summary_stats: Dict[str, Any]
