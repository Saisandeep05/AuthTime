"""
Unit tests for transparent severity scoring formula.
"""

from authtime.reporting.generator import compute_severity_score


def test_severity_score_calculation():
    score_low, label_low = compute_severity_score(0.0, "/admin/users", "PROVEN")
    assert score_low == 0.0
    assert label_low == "LOW"

    score_med, label_med = compute_severity_score(6.0, "/admin/users", "SUPPORTED")
    assert 4.0 <= score_med <= 7.0
    assert label_med == "MEDIUM"

    score_high, label_high = compute_severity_score(60.0, "/admin/users", "PROVEN")
    assert score_high >= 7.0
