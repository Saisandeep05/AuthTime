"""
Canonical Authorization Predicate & Decision Evaluator for AuthTime.
Ensures single unified definition of authorization decision and violation across engine, PoC, and tests.
Uses contract-based ResourceContract evaluation rather than generic field matching heuristics.
"""

import json
from typing import Optional, Dict, Any, Tuple, Literal
from authtime.adapters.contract import DEFAULT_ADMIN_USERS_CONTRACT, ResourceContract

DecisionType = Literal["ALLOW", "DENY", "ERROR", "TIMEOUT", "CONNECTION_ERROR", "HTTP_ERROR", "UNKNOWN"]


def evaluate_http_decision(
    status_code: int,
    response_body: Optional[str] = None,
    resource_path: str = "/admin/users",
    contract: Optional[ResourceContract] = None,
) -> DecisionType:
    """
    Evaluates HTTP response status code, body content, and resource contract to determine authorization decision.
    Avoids heuristic substring matching and delegates to explicit ResourceContract.
    """
    if status_code == 408:
        return "TIMEOUT"

    if status_code in (502, 503, 504):
        return "CONNECTION_ERROR"

    if status_code >= 500:
        return "HTTP_ERROR"

    res_contract = contract or DEFAULT_ADMIN_USERS_CONTRACT
    evaluated_result = res_contract.evaluate_response(status_code, response_body)
    return evaluated_result  # type: ignore


def evaluate_authorization_violation(
    actual_decision: str,
    ground_truth_decision: str,
    status_code: int = 200,
    response_body: Optional[str] = None,
    resource_path: str = "/admin/users",
    contract: Optional[ResourceContract] = None,
) -> Tuple[bool, str]:
    """
    Evaluates whether an observed HTTP request constitutes an authorization security violation.
    Returns (is_violation: bool, reason: str).
    A violation occurs ONLY when ground_truth_decision is 'DENY' AND actual_decision is explicitly 'ALLOW'.
    """
    effective_actual = (
        evaluate_http_decision(status_code, response_body, resource_path, contract)
        if actual_decision in ("ALLOW", "UNKNOWN")
        else actual_decision
    )

    if ground_truth_decision.upper() == "DENY":
        if effective_actual == "ALLOW":
            return True, "EXPOSURE_VIOLATION: Ground truth required DENY but target returned validated ALLOW response."
        if effective_actual == "UNKNOWN":
            return False, "UNKNOWN_EVIDENCE: Response returned status code or content that did not satisfy protected resource contract."
        if effective_actual in ("TIMEOUT", "CONNECTION_ERROR", "HTTP_ERROR", "ERROR"):
            return False, f"NETWORK_OR_SERVER_ERROR: Request resulted in {effective_actual} rather than authorization ALLOW."

    if ground_truth_decision.upper() == "ALLOW" and effective_actual == "DENY":
        return False, "FALSE_DENIAL: Expected ALLOW but target denied request."

    return False, f"EXPECTED_DECISION: Target decision ({effective_actual}) matches ground truth ({ground_truth_decision})."
