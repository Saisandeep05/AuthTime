"""
Unit tests for Canonical Authorization Predicate.
"""

from authtime.verification.predicate import evaluate_http_decision, evaluate_authorization_violation


def test_evaluate_http_decision_status_codes():
    assert evaluate_http_decision(401) == "DENY"
    assert evaluate_http_decision(403) == "DENY"
    assert evaluate_http_decision(408) == "TIMEOUT"
    assert evaluate_http_decision(502) == "CONNECTION_ERROR"
    assert evaluate_http_decision(500) == "HTTP_ERROR"



def test_evaluate_http_decision_denial_payloads():
    body_denied = '{"detail": "Permission denied"}'
    assert evaluate_http_decision(200, body_denied, "/admin/users") == "DENY"

    body_unauth = '{"error": "Unauthorized"}'
    assert evaluate_http_decision(200, body_unauth, "/admin/users") == "DENY"


def test_evaluate_http_decision_resource_contracts():
    body_admin = '{"users": ["admin1", "user1"]}'
    assert evaluate_http_decision(200, body_admin, "/admin/users") == "ALLOW"

    body_unknown_json = '{"status": "something_else", "count": 5}'
    assert evaluate_http_decision(200, body_unknown_json, "/admin/users") == "UNKNOWN"

    body_html = "<html><body>Server Error Page</body></html>"
    assert evaluate_http_decision(200, body_html, "/admin/users") == "UNKNOWN"


def test_evaluate_authorization_violation():
    body_admin = '{"users": ["admin1", "user1"]}'
    is_viol, reason = evaluate_authorization_violation("ALLOW", "DENY", 200, body_admin, "/admin/users")
    assert is_viol is True
    assert "EXPOSURE_VIOLATION" in reason

    body_unknown = '{"status": "unknown"}'
    is_viol_unk, reason_unk = evaluate_authorization_violation("UNKNOWN", "DENY", 200, body_unknown, "/admin/users")
    assert is_viol_unk is False
    assert "UNKNOWN_EVIDENCE" in reason_unk

    is_viol_deny, _ = evaluate_authorization_violation("DENY", "DENY", 403, None, "/admin/users")
    assert is_viol_deny is False
