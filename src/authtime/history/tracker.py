"""
Cross-Run Exposure History Tracker & Regression Analyzer.
"""

import os
import json
import time
import subprocess
from typing import Dict, Any, List, Optional
from authtime.models.schemas import ExperimentResult


def get_git_commit_hash() -> str:
    """Attempts to retrieve the current git commit short SHA."""
    try:
        res = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=2)
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return os.getenv("GIT_COMMIT", "unknown")


class ExposureHistoryTracker:
    """Tracks exposure metrics across runs to detect security regressions."""

    def __init__(self, history_file: str = "history/exposure_history.jsonl"):
        self.history_file = history_file
        os.makedirs(os.path.dirname(os.path.abspath(self.history_file)), exist_ok=True)

    def record_run(self, result: ExperimentResult, commit_hash: Optional[str] = None) -> Dict[str, Any]:
        """Appends a run entry to exposure_history.jsonl."""
        c_hash = commit_hash if commit_hash and commit_hash != "unknown" else get_git_commit_hash()
        entry = {
            "timestamp": time.time(),
            "commit_hash": c_hash,
            "experiment_id": result.experiment_id,
            "fault_type": result.finding.fault_type,
            "estimated_exposure_sec": result.exposure_metrics.estimated_exposure_sec,
            "exposure_interval_min_sec": result.exposure_metrics.exposure_interval_min_sec,
            "precision_sec": result.exposure_metrics.precision_sec,
            "is_censored": result.exposure_metrics.is_censored,
            "measurement_status": result.exposure_metrics.measurement_status,
            "severity_score": result.finding.severity_score,
            "severity_label": result.finding.severity_label,
            "root_cause": result.finding.root_cause,
        }

        with open(self.history_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        return entry

    def load_history(self) -> List[Dict[str, Any]]:
        """Loads all historical run records safely, skipping malformed lines."""
        if not os.path.exists(self.history_file):
            return []

        entries = []
        with open(self.history_file, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    try:
                        entries.append(json.loads(stripped))
                    except Exception:
                        continue
        return entries

    def compare_runs(self, latest_exposure: float, fault_type: str = "stale_cache", threshold_sec: float = 0.5) -> Dict[str, Any]:
        """Compares current exposure against baseline history for matching fault_type using censoring-aware metrics."""
        all_history = self.load_history()
        history = [e for e in all_history if e.get("fault_type") == fault_type]

        if not history:
            return {
                "has_regression": False,
                "diff_sec": 0.0,
                "historical_avg_sec": latest_exposure,
                "message": f"No historical data for fault_type '{fault_type}'. Current run established as baseline.",
            }

        uncensored_exposures = [
            e["estimated_exposure_sec"] for e in history if e.get("estimated_exposure_sec") is not None and not e.get("is_censored", False)
        ]
        
        if uncensored_exposures:
            avg_prev = sum(uncensored_exposures) / len(uncensored_exposures)
        else:
            mins = [e.get("exposure_interval_min_sec", 0.0) for e in history]
            avg_prev = sorted(mins)[len(mins) // 2] if mins else latest_exposure

        diff = latest_exposure - avg_prev
        is_regression = diff > threshold_sec

        return {
            "has_regression": is_regression,
            "diff_sec": diff,
            "historical_avg_sec": avg_prev,
            "message": (
                f"🚨 REGRESSION DETECTED! '{fault_type}' exposure increased by +{diff:.2f}s above historical baseline ({avg_prev:.2f}s)."
                if is_regression
                else f"✅ NO REGRESSION. '{fault_type}' exposure is within acceptable threshold (diff: {diff:+.2f}s)."
            ),
        }

