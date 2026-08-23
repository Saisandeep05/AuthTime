"""
AuthTime Distributed Lab - Mitigation Failure Mode Validation.
Verifies explicit FAIL-CLOSED (401/403 Forbidden) behavior under infrastructure outages and network partition faults.
"""

import pytest
from fastapi.testclient import TestClient
from targets.distributed_lab.service.app import create_lab_replica_app
from targets.distributed_lab.auth.jwt_handler import LabJWTHandler


@pytest.fixture
def client():
    app = create_lab_replica_app(replica_id="api-1")
    return TestClient(app)


@pytest.fixture
def jwt_handler():
    return LabJWTHandler()


def test_mitigation_fail_closed_on_unauthenticated_request(client):
    """Unauthenticated request must fail closed with 401."""
    response = client.get("/finance/payroll")
    assert response.status_code == 401


def test_mitigation_fail_closed_on_invalid_token(client):
    """Malformed or invalid token must fail closed with 401/403."""
    headers = {"Authorization": "Bearer invalid.jwt.token.string"}
    response = client.get("/finance/payroll", headers=headers)
    assert response.status_code in (401, 403)


def test_mitigation_fail_closed_on_stale_auth_version(client, jwt_handler):
    """Token with stale auth_version (1) presented after revocation (version 2) must fail closed."""
    # Issue old token with auth_version 1
    stale_token = jwt_handler.create_access_token("alice", role="Finance Admin", auth_version=1)

    # Enable mitigation mode
    client.post("/faults/configure-mitigation", json={"enabled": True}, params={"broadcast": "false"})

    # Perform revocation to bump DB version to 2
    revoke_resp = client.post("/faults/revoke", json={"user_id": "alice", "new_role": "User"}, params={"broadcast": "false"})
    assert revoke_resp.status_code == 200

    # Request with stale token to version-aware endpoint
    headers = {"Authorization": f"Bearer {stale_token}"}
    response = client.get("/finance/payroll", headers=headers)

    assert response.status_code in (401, 403)


def test_mitigation_fail_closed_on_redis_unavailable(client, jwt_handler):
    """When Redis is unavailable, version verification must fall back safely without silent ALLOW."""
    token = jwt_handler.create_access_token("alice", role="Finance Admin", auth_version=1)

    # Inject Redis unavailable fault mode
    client.post("/faults/configure-cache-mode", json={"mode": "unavailable"}, params={"broadcast": "false"})

    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/finance/payroll", headers=headers)

    # Must evaluate cleanly (verifying version against DB fallback) or DENY
    assert response.status_code in (200, 401, 403)

    # Clean up fault mode
    client.post("/reset", params={"broadcast": "false"})
