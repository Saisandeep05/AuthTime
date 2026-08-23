"""
Unit tests for Transparent Severity Scoring Model.
"""

from authtime.reporting.generator import compute_severity_score


def test_severity_score_calculation():
    # 0s exposure -> LOW (0.0)
    score0, label0 = compute_severity_score(0.0, "/admin/users", "High")
    assert score0 == 0.0
    assert label0 == "LOW"

    # Moderate exposure on admin route (10s exposure * 1.5 admin weight = 8.4)
    score_mid, label_mid = compute_severity_score(10.0, "/admin/users", "High")
    assert 4.0 <= score_mid <= 9.0
    assert label_mid == "HIGH"

    # Moderate exposure on standard user route (10s exposure * 1.0 user weight = 5.6)
    score_user, label_user = compute_severity_score(10.0, "/invoices/1", "High")
    assert 4.0 <= score_user <= 7.0
    assert label_user == "MEDIUM"
