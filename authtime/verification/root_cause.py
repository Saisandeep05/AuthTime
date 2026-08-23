"""
Evidence-Backed Root Cause Analyzer.
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
        Returns (root_cause_code, confidence_level, explanation_text).
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

        if fault_type == "token_expiry":
            return (
                "TOKEN_EXPIRY",
                "High",
                "Access persisted strictly until stateless JWT expiration.",
            )

        if fault_type == "stale_cache":
            cache_ttl = config.get("cache_ttl_seconds", 60.0)
            return (
                "AUTHORIZATION_CACHE",
                "Likely",
                f"Authorization cache retained stale role/permissions for up to {cache_ttl} seconds.",
            )

        if fault_type == "role_revocation":
            cache_ttl = config.get("cache_ttl_seconds", 60.0)
            if metrics.estimated_exposure_sec > 0 and abs(metrics.estimated_exposure_sec - cache_ttl) <= (metrics.precision_sec + 5.0):
                return (
                    "AUTHORIZATION_CACHE",
                    "Likely",
                    f"Revoked role change was delayed by active authorization cache TTL ({cache_ttl}s).",
                )
            elif metrics.estimated_exposure_sec > 0:
                return (
                    "ROLE_REVOCATION",
                    "Likely",
                    "Role change occurred in database but application logic continued granting access.",
                )
            else:
                return (
                    "ROLE_REVOCATION",
                    "High",
                    "Authorization revocation took effect immediately with zero exposure.",
                )

        return (
            "UNKNOWN",
            "Undetermined",
            "Observed behavior requires manual inspection.",
        )
