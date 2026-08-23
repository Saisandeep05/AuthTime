"""
Censoring-Aware Statistical Analysis & Survival Probability Estimator for AuthTime.
Provides Kaplan-Meier survival curves, lower-bound median estimation, and formatted uncertainty metrics.
"""

import math
from typing import List, Dict, Any, Optional, Tuple


def calculate_kaplan_meier_survival(
    trial_events: List[Dict[str, Any]],
    observation_horizon_sec: float = 60.0,
) -> Dict[str, Any]:
    """
    Computes Kaplan-Meier survival estimator S(t) = P(T > t) for right-censored exposure data.
    """
    if not trial_events:
        return {"survival_curve": [], "median_exposure_sec": None, "note": "No trial events provided"}

    # Sort observations by exposure interval minimum
    sorted_trials = sorted(trial_events, key=lambda x: x.get("exposure_interval_min_sec", 0.0))
    n_total = len(sorted_trials)
    
    uncensored = [t for t in sorted_trials if not t.get("is_censored", False)]
    censored = [t for t in sorted_trials if t.get("is_censored", False)]

    survival_curve = []
    current_s = 1.0
    n_at_risk = n_total

    for trial in sorted_trials:
        t_val = trial.get("exposure_interval_min_sec", 0.0)
        is_c = trial.get("is_censored", False)
        
        if not is_c and n_at_risk > 0:
            events_count = 1
            current_s = current_s * (1.0 - (events_count / n_at_risk))
            survival_curve.append({
                "time_sec": round(t_val, 2),
                "survival_probability": round(current_s, 4),
                "n_at_risk": n_at_risk,
                "n_events": events_count,
            })
        n_at_risk -= 1

    if uncensored and not censored:
        exact_exposures = [t["estimated_exposure_sec"] for t in uncensored if t.get("estimated_exposure_sec") is not None]
        mean_sec = round(sum(exact_exposures) / len(exact_exposures), 2) if exact_exposures else None
        note = "Uncensored observations: Ordinary sample mean is estimable."
    else:
        mean_sec = None  # Right-censored data: Sample mean is NOT ESTIMABLE!
        note = "Right-censored observations present: Sample mean is NOT ESTIMABLE. Kaplan-Meier survival estimator applied."

    mins = [t.get("exposure_interval_min_sec", 0.0) for t in sorted_trials]
    lower_bound_median = round(sorted(mins)[len(mins) // 2], 2) if mins else 0.0

    return {
        "trial_count": n_total,
        "uncensored_count": len(uncensored),
        "censored_count": len(censored),
        "kaplan_meier_curve": survival_curve,
        "mean_exposure_sec": mean_sec,
        "lower_bound_median_sec": lower_bound_median,
        "note": note,
    }


def format_uncertainty_interval(
    exposure_min_sec: float,
    exposure_max_sec: Optional[float],
    precision_sec: Optional[float],
    is_censored: bool,
) -> str:
    """
    Formats exposure window with scientifically sound uncertainty intervals instead of raw float noise.
    """
    if is_censored or exposure_max_sec is None or precision_sec is None:
        return f"≥ {exposure_min_sec:.2f}s (Conservative Lower Bound)"
    
    estimated = (exposure_min_sec + exposure_max_sec) / 2.0
    return f"{estimated:.2f}s ± {precision_sec:.2f}s (Interval: [{exposure_min_sec:.2f}s, {exposure_max_sec:.2f}s])"
