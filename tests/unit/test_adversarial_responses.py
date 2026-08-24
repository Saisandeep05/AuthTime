"""
Adversarial response test matrix for AuthTime authorization predicate.
Verifies that all ambiguous, malformed, non-contract, or unexpected target responses evaluate to 'UNKNOWN',
and that transport errors are classified cleanly as typed observations (never fabricated HTTP statuses or ALLOW).
"""

from authtime.adapters.contract import DEFAULT_ADMIN_USERS_CONTRACT, ResourceContract
from authtime.verification.predicate import evaluate_http_decision, evaluate_authorization_violation


def test_adversarial_json_shapes_evaluate_to_unknown():
    adversarial_bodies = [
        '{"data": "anything"}',
        '{"users": null}',
        '{"users": "admin"}',
        '{"users": []}',
        '{"message": "ok"}',
        '{"permission": "granted"}',
        '{"access_token": "fake"}',
        '{}',
        '{"status": "SUCCESS", "message": "no data"}',
        '{"invoices": ["inv1"]}',  # Admin contract expects 'users' key!
        '{"role": "admin"}',
    ]

    for body in adversarial_bodies:
        dec = evaluate_http_decision(200, body, "/admin/users", DEFAULT_ADMIN_USERS_CONTRACT)
        assert dec == "UNKNOWN", f"Adversarial body '{body}' incorrectly evaluated to '{dec}' instead of UNKNOWN"


def test_valid_contract_payload_evaluates_to_allow():
    valid_admin_body = '{"users": ["admin1", "user1"]}'
    dec = evaluate_http_decision(200, valid_admin_body, "/admin/users", DEFAULT_ADMIN_USERS_CONTRACT)
    assert dec == "ALLOW"


def test_explicit_denial_payloads_evaluate_to_deny():
    denial_bodies = [
        '{"detail": "Permission denied"}',
        '{"error": "unauthorized"}',
        '{"message": "Access denied"}',
        '{"detail": "Forbidden"}',
        '{"detail": "Missing token"}',
    ]

    for body in denial_bodies:
        dec = evaluate_http_decision(200, body, "/admin/users", DEFAULT_ADMIN_USERS_CONTRACT)
        assert dec == "DENY"


def test_malformed_html_and_text_evaluate_to_unknown():
    non_json_bodies = [
        "<html><body>500 Internal Server Error</body></html>",
        "Unauthorized",
        "OK",
        "12345",
        "True",
        "{malformed json",
    ]

    for body in non_json_bodies:
        dec = evaluate_http_decision(200, body, "/admin/users", DEFAULT_ADMIN_USERS_CONTRACT)
        assert dec == "UNKNOWN"


def test_status_codes_and_transport_error_types():
    assert evaluate_http_decision(401, None, "/admin/users") == "DENY"
    assert evaluate_http_decision(403, None, "/admin/users") == "DENY"
    assert evaluate_http_decision(408, None, "/admin/users") == "TIMEOUT"
    assert evaluate_http_decision(502, None, "/admin/users") == "CONNECTION_ERROR"
    assert evaluate_http_decision(503, None, "/admin/users") == "CONNECTION_ERROR"
    assert evaluate_http_decision(500, None, "/admin/users") == "HTTP_ERROR"


def test_unknown_decision_never_becomes_violation():
    body_unknown = '{"data": "anything"}'
    is_viol, reason = evaluate_authorization_violation("UNKNOWN", "DENY", 200, body_unknown, "/admin/users", DEFAULT_ADMIN_USERS_CONTRACT)
    assert is_viol is False
    assert "UNKNOWN_EVIDENCE" in reason
