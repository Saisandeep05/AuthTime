"""
Report Generator and Severity Scoring Module.
"""

import math
from typing import Tuple


def compute_severity_score(
    estimated_exposure_sec: float,
    resource_path: str,
    confidence: str,
) -> Tuple[float, str]:
    """
    Computes transparent severity score (0.0 to 10.0) based on formula in docs/severity-scoring.md:
    Severity Score = min(10.0, S_exposure * W_endpoint * C_confidence)
    """
    if estimated_exposure_sec <= 0:
        return 0.0, "LOW"

    # Exposure factor: log-scaled duration
    s_exposure = 3.0 + 2.5 * math.log10(estimated_exposure_sec + 1.0)

    # Endpoint weight
    w_endpoint = 1.5 if resource_path.startswith("/admin") else 1.0

    # Confidence multiplier
    c_conf = 1.0 if confidence == "High" else (0.85 if confidence == "Likely" else 0.70)

    raw_score = min(10.0, round(s_exposure * w_endpoint * c_conf, 1))

    if raw_score >= 9.0:
        label = "CRITICAL"
    elif raw_score >= 7.0:
        label = "HIGH"
    elif raw_score >= 4.0:
        label = "MEDIUM"
    else:
        label = "LOW"

    return raw_score, label
