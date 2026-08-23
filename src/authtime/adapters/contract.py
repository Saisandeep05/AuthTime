"""
Resource Contract and Target Adapter Architecture for AuthTime.
Establishes serializable, versioned contracts for authorization verification.
"""

import json
from typing import Dict, Any, List, Optional, Set
from pydantic import BaseModel, Field


class ResourceContract(BaseModel):
    contract_id: str = "contract-admin-users-v1"
    contract_version: str = "1.0"
    target_type: str = "reference-target"
    resource_path: str = "/admin/users"
    accepted_status_codes: List[int] = Field(default_factory=lambda: [200])
    denial_status_codes: List[int] = Field(default_factory=lambda: [401, 403])
    required_json_keys: List[str] = Field(default_factory=lambda: ["users"])
    denial_json_values: List[str] = Field(
        default_factory=lambda: [
            "permission denied",
            "unauthorized",
            "access denied",
            "forbidden",
            "missing token",
            "invalid token",
        ]
    )

    def evaluate_response(
        self,
        status_code: int,
        response_body: Optional[str] = None,
    ) -> str:
        """
        Evaluates HTTP response against contract.
        Returns: 'ALLOW', 'DENY', 'HTTP_ERROR', 'UNKNOWN'
        """
        if status_code in self.denial_status_codes:
            return "DENY"

        if status_code in (500, 502, 503, 504):
            return "HTTP_ERROR"

        if status_code not in self.accepted_status_codes:
            return "UNKNOWN"

        if not response_body:
            return "UNKNOWN"

        try:
            body_json = json.loads(response_body) if isinstance(response_body, str) else response_body
            if isinstance(body_json, dict):
                # 1. Explicit denial values check
                detail_val = str(
                    body_json.get("detail", "")
                    or body_json.get("error", "")
                    or body_json.get("message", "")
                ).lower()
                if any(d_val in detail_val for d_val in self.denial_json_values):
                    return "DENY"

                # 2. Strict required key matching for contract
                for req_key in self.required_json_keys:
                    if req_key in body_json and body_json[req_key] is not None and len(body_json[req_key]) > 0:
                        return "ALLOW"

                return "UNKNOWN"
        except Exception:
            return "UNKNOWN"

        return "UNKNOWN"


DEFAULT_ADMIN_USERS_CONTRACT = ResourceContract()
