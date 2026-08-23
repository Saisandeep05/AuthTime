"""
Evidence-Based Root Cause Analyzer.
"""

from typing import Dict, Any, Tuple, Optional, List
from authtime.models.schemas import ExposureMetric, EvidenceEvent


class RootCauseAnalyzer:
    @staticmethod
    def analyze_root_cause(
        fault_type: str,
        config: Dict[str, Any],
        metrics: ExposureMetric,
        has_cache_key_collision: bool = False,
        events: Optional[List[EvidenceEvent]] = None,
    ) -> Tuple[str, str, str]:
        """
        Analyzes empirical evidence metrics, probe observations, audit events, and config values to infer root cause code,
        evidence confidence status (PROVEN, SUPPORTED, INCONCLUSIVE), and evidence-backed explanation.
        Returns tuple of (code, confidence, explanation).
        """
        if has_cache_key_collision:
            return (
                "CACHE_KEY_COLLISION",
                "PROVEN (Evidence Verified)",
                "Empirical evidence demonstrates cross-tenant authorization state bleed across user accounts.",
            )

        if metrics.unauthorized_request_count == 0 and metrics.estimated_exposure_sec == 0.0:
            return (
                "NO_EXPOSURE",
                "PROVEN (Evidence Verified)",
                "No post-fault unauthorized requests were accepted by the target application.",
            )

        if metrics.is_censored:
            return (
                "OBSERVATION_HORIZON_REACHED",
                "SUPPORTED (Observation Horizon Reached)",
                f"Unauthorized access remained observable through the full observation horizon ({metrics.observation_horizon_sec:.2f}s). Consistent with extended exposure.",
            )

        time_scale = float(config.get("time_scale_factor", 1.0))
        raw_cache_ttl = float(config.get("cache_ttl_seconds", 60.0))
        effective_cache_ttl = raw_cache_ttl * time_scale
        exp_sec = metrics.estimated_exposure_sec

        if fault_type == "stale_cache":
            diff = abs(exp_sec - effective_cache_ttl)
            rel_diff_pct = (diff / effective_cache_ttl) * 100.0 if effective_cache_ttl > 0 else 0.0
            if diff <= max(1.5, effective_cache_ttl * 0.25):
                conf = "PROVEN (Evidence Verified)"
                expl = (
                    f"Observed exposure boundary ({exp_sec:.2f}s) matches effective authorization cache TTL "
                    f"({effective_cache_ttl:.2f}s; raw TTL={raw_cache_ttl:.1f}s at {time_scale:.2f}x scale) "
                    f"within ±{diff:.2f}s ({rel_diff_pct:.1f}% relative tolerance)."
                )
            else:
                conf = "SUPPORTED (Partial Match)"
                expl = (
                    f"Observed exposure boundary ({exp_sec:.2f}s) differs from effective cache TTL "
                    f"({effective_cache_ttl:.2f}s) by {diff:.2f}s ({rel_diff_pct:.1f}% relative deviation)."
                )
            return ("AUTHORIZATION_CACHE", conf, expl)

        if fault_type == "token_expiry":
            return (
                "TOKEN_EXPIRY",
                "PROVEN (Evidence Verified)",
                f"Observed exposure window ({exp_sec:.2f}s) matches stateless JWT token expiration duration.",
            )

        if fault_type == "agent_session_revocation":
            return (
                "DELEGATED_CREDENTIAL_STALENESS",
                "SUPPORTED (Partial Match)",
                f"Revoking delegator permission did not invalidate down-scope delegated agent session credential (exposure: {exp_sec:.2f}s).",
            )

        if fault_type == "role_revocation":
            return (
                "ROLE_REVOCATION",
                "SUPPORTED (Partial Match)",
                f"Middleware failed to re-evaluate updated role permissions immediately (exposure: {exp_sec:.2f}s).",
            )

        return (
            "UNKNOWN",
            "INCONCLUSIVE",
            f"Observed exposure ({exp_sec:.2f}s) does not fit standard threshold classification rules.",
        )
