"""
Root Cause Analyzer.
"""

from typing import Dict, Any, Tuple
from authtime.models.schemas import ExposureMetric


class RootCauseAnalyzer:
    @staticmethod
    def analyze_root_cause(
        fault_type: str,
        config: Dict[str, Any],
        metrics: ExposureMetric,
        has_cache_key_collision: bool = False,
    ) -> Tuple[str, str, str]:
        """
        Analyzes evidence and timing metrics to assign root cause code, confidence, and explanation.
        Returns tuple of (code, confidence, explanation).
        """
        if has_cache_key_collision:
            return (
                "CACHE_KEY_COLLISION",
                "High",
                "Revoking User A's authorization impacted User B's decision, revealing a cache key collision or state bleed.",
            )

        if fault_type == "agent_session_revocation":
            return (
                "DELEGATED_CREDENTIAL_STALENESS",
                "High",
                "Revoking delegator permission did not invalidate down-scope delegated agent session credential.",
            )

        if fault_type == "stale_cache":
            cache_ttl = config.get("cache_ttl_seconds", 60.0)
            return (
                "AUTHORIZATION_CACHE",
                "Likely",
                f"Authorization cache retained stale role/permissions for up to {cache_ttl} seconds.",
            )

        if fault_type == "token_expiry":
            return (
                "TOKEN_EXPIRY",
                "High",
                "Access persisted strictly until stateless JWT expiration.",
            )

        if fault_type == "role_revocation":
            return (
                "ROLE_REVOCATION",
                "Likely",
                "Middleware failed to re-evaluate updated role permissions immediately.",
            )

        return (
            "UNKNOWN",
            "Undetermined",
            "Observed exposure does not fit standard classification rules.",
        )
