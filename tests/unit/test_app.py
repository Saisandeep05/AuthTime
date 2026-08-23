"""
Unit and Integration tests for Reference Auth Target (app/).
"""

import time
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.auth.jwt import create_jwt_token, verify_jwt_token
from app.rbac.roles import has_permission, Role
from app.cache.ttl_cache import AuthCache
from app.models.db import db

client = TestClient(app)


def test_jwt_generation_and_verification():
    token = create_jwt_token("admin1", "Admin", ttl_seconds=60)
    claims = verify_jwt_token(token)
    assert claims is not None
    assert claims["sub"] == "admin1"
    assert claims["role"] == "Admin"


def test_expired_jwt():
    token = create_jwt_token("admin1", "Admin", ttl_seconds=-10)
    claims = verify_jwt_token(token)
    assert claims is None


def test_rbac_roles():
    assert has_permission("Admin", "MANAGE_USERS") is True
    assert has_permission("User", "MANAGE_USERS") is False
    assert has_permission("User", "READ_INVOICE") is True
    assert has_permission("Guest", "WRITE_INVOICE") is False


def test_auth_cache_operations():
    cache = AuthCache(default_ttl_seconds=1.0)
    cache.set("key1", "value1")

    val, hit = cache.get("key1")
    assert hit is True
    assert val == "value1"

    time.sleep(1.1)
    val2, hit2 = cache.get("key1")
    assert hit2 is False
    assert val2 is None


def test_login_endpoint():
    resp = client.post("/auth/login", json={"user_id": "admin1"})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["role"] == "Admin"


def test_protected_routes():
    # Login as admin
    login_resp = client.post("/auth/login", json={"user_id": "admin1"}).json()
    token = login_resp["access_token"]
    headers = {"Authorization": f"Bearer {token}", "X-AuthTime-Request-ID": "test-req-1"}

    # Access /admin/users
    admin_resp = client.get("/admin/users", headers=headers)
    assert admin_resp.status_code == 200
    assert admin_resp.headers.get("X-AuthTime-Request-ID") == "test-req-1"

    # Access /invoices/101
    inv_resp = client.get("/invoices/101", headers=headers)
    assert inv_resp.status_code == 200


def test_role_revocation_fault_injection():
    # Reset state
    client.post("/faults/reset")

    # Get admin token
    token = client.post("/auth/login", json={"user_id": "admin1"}).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Verify baseline admin access
    assert client.get("/admin/users", headers=headers).status_code == 200

    # Clear cache to force DB lookup test
    client.post("/faults/reset")
    token = client.post("/auth/login", json={"user_id": "admin1"}).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Inject fault: Revoke admin1 to User role
    fault_resp = client.post("/faults/inject", json={"fault_type": "role_revocation", "user_id": "admin1", "new_role": "User"})
    assert fault_resp.status_code == 200

    # Invalidate cache to test DB lookup
    from app.cache.ttl_cache import auth_cache
    auth_cache.invalidate("auth:admin1")

    # Request /admin/users should now return 403 Forbidden
    blocked_resp = client.get("/admin/users", headers=headers)
    assert blocked_resp.status_code == 403

    # Cleanup reset
    client.post("/faults/reset")


def test_fault_api_local_safety_guard():
    # TestClient request_host defaults to testclient (which is in local allowlist)
    res = client.post("/faults/reset")
    assert res.status_code == 200
