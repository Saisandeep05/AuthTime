"""
Raw Evidence Layer, Lifecycle State Machine, and Provenance Schemas for AuthTime.
Ensures immutable raw observation capture, formal state transitions, and evidence-backed root cause classification.
"""

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Any, List, Optional, Literal
from pydantic import BaseModel, Field


class ExperimentState(str, Enum):
    CREATED = "CREATED"
    TARGET_VERIFIED = "TARGET_VERIFIED"
    BASELINE_VERIFIED = "BASELINE_VERIFIED"
    FAULT_INJECTED = "FAULT_INJECTED"
    PROBING = "PROBING"
    ANALYZED = "ANALYZED"
    CLEANUP = "CLEANUP"
    CLEAN_VERIFIED = "CLEAN_VERIFIED"
    VALID = "VALID"
    INVALID = "INVALID"


class TransportErrorCategory(str, Enum):
    HTTP_RESPONSE = "HTTP_RESPONSE"
    NETWORK_TIMEOUT = "NETWORK_TIMEOUT"
    CONNECTION_ERROR = "CONNECTION_ERROR"
    DNS_ERROR = "DNS_ERROR"
    CLIENT_ERROR = "CLIENT_ERROR"


class RawProbeObservation(BaseModel):
    """
    Immutable Raw Observation record for a single probe.
    Preserves exact timing, transport result, raw HTTP status, sanitized body snippet, and SHA256 hash.
    """
    probe_id: str
    run_id: str
    experiment_id: str
    trial_id: str
    probe_index: int
    requested_offset_sec: float
    actual_offset_sec: float
    timing_error_sec: float
    request_start_monotonic: float
    response_received_monotonic: float
    network_latency_ms: float
    transport_result: TransportErrorCategory
    raw_http_status: int  # 0 if transport error
    headers_subset: Dict[str, str] = Field(default_factory=dict)
    sanitized_body_snippet: Optional[str] = None
    body_sha256: Optional[str] = None
    actual_decision: str
    decision_reason: str
    ground_truth_decision: str

    @classmethod
    def create(
        cls,
        probe_id: str,
        run_id: str,
        experiment_id: str,
        trial_id: str,
        probe_index: int,
        requested_offset_sec: float,
        actual_offset_sec: float,
        request_start_monotonic: float,
        response_received_monotonic: float,
        transport_result: TransportErrorCategory,
        raw_http_status: int,
        body_text: Optional[str],
        actual_decision: str,
        decision_reason: str,
        ground_truth_decision: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> "RawProbeObservation":
        latency_ms = round((response_received_monotonic - request_start_monotonic) * 1000.0, 3)
        timing_err = round(actual_offset_sec - requested_offset_sec, 4)
        body_hash = hashlib.sha256(body_text.encode("utf-8")).hexdigest() if body_text else None
        snippet = (body_text[:197] + "...") if body_text and len(body_text) > 200 else body_text

        safe_headers = {}
        if headers:
            for k, v in headers.items():
                if k.lower() in ("x-authtime-request-id", "x-authtime-experiment-id", "x-authtime-trial-id", "content-type"):
                    safe_headers[k] = v

        return cls(
            probe_id=probe_id,
            run_id=run_id,
            experiment_id=experiment_id,
            trial_id=trial_id,
            probe_index=probe_index,
            requested_offset_sec=requested_offset_sec,
            actual_offset_sec=actual_offset_sec,
            timing_error_sec=timing_err,
            request_start_monotonic=request_start_monotonic,
            response_received_monotonic=response_received_monotonic,
            network_latency_ms=latency_ms,
            transport_result=transport_result,
            raw_http_status=raw_http_status,
            headers_subset=safe_headers,
            sanitized_body_snippet=snippet,
            body_sha256=body_hash,
            actual_decision=actual_decision,
            decision_reason=decision_reason,
            ground_truth_decision=ground_truth_decision,
        )


class RootCauseAssessment(BaseModel):
    """
    Formal evidence-backed root cause classification model.
    """
    category: str  # e.g., AUTHORIZATION_CACHE, TOKEN_REVOCATION_DELAY, OBSERVATION_HORIZON_REACHED
    confidence: Literal["CONFIRMED", "SUPPORTED", "INFERRED", "UNDETERMINED"]
    evidence_ids: List[str] = Field(default_factory=list)
    methodology: str
    direct_evidence_collected: bool = False
    explanation: str
