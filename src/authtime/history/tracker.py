"""
Cross-Run Exposure History Tracker & Regression Analyzer.
"""

import os
import json
import time
from typing import Dict, Any, List, Optional
from authtime.models.schemas import ExperimentResult


class ExposureHistoryTracker:
    """Tracks exposure metrics across runs to detect security regressions."""

    def __init__(self, history_file: str = "history/exposure_history.jsonl"):
        self.history_file = history_file
        os.makedirs(os.path.dirname(os.path.abspath(self.history_file)), exist_ok=True)

    def record_run(self, result: ExperimentResult, commit_hash: str = "unknown") -> Dict[str, Any]:
        """Appends a run entry to exposure_history.jsonl."""
        entry = {
            "timestamp": time.time(),
            "commit_hash": commit_hash,
            "experiment_id": result.experiment_id,
            "fault_type": result.scenario.fault_directive.fault_type,
            "estimated_exposure_sec": result.exposure_metrics.estimated_exposure_sec,
            "precision_sec": result.exposure_metrics.precision_sec,
            "severity_score": result.finding.severity_score,
            "severity_label": result.finding.severity_label,
            "root_cause": result.finding.root_cause,
        }

        with open(self.history_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        return entry

    def load_history(self) -> List[Dict[str, Any]]:
        """Loads all historical run records."""
        if not os.path.exists(self.history_file):
            return []

        entries = []
        with open(self.history_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))
        return entries

    def compare_runs(self, latest_exposure: float, threshold_sec: float = 0.5) -> Dict[str, Any]:
        """Compares current exposure against baseline history."""
        history = self.load_history()
        if not history:
            return {
                "has_regression": False,
                "diff_sec": 0.0,
                "historical_avg_sec": latest_exposure,
                "message": "No historical data found. Current run established as new baseline.",
            }

        prev_exposures = [e["estimated_exposure_sec"] for e in history]
        avg_prev = sum(prev_exposures) / len(prev_exposures)
        diff = latest_exposure - avg_prev

        is_regression = diff > threshold_sec

        return {
            "has_regression": is_regression,
            "diff_sec": diff,
            "historical_avg_sec": avg_prev,
            "message": (
                f"🚨 REGRESSION DETECTED! Exposure increased by +{diff:.2f}s above historical average ({avg_prev:.2f}s)."
                if is_regression
                else f"✅ NO REGRESSION. Exposure is within acceptable threshold (diff: {diff:+.2f}s)."
            ),
        }
