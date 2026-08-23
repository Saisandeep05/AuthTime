"""
Unit tests for FastAPI Reference Auth Target (`app/`).
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.auth.jwt import create_access_token, decode_access_token
from app.rbac.roles import has_permission, RoleEnum
from app.cache.ttl_cache import TTLCache

client = TestClient(app)


def test_jwt_token_flow():
    token = create_access_token("admin1", "Admin", ttl_seconds=60)
    payload = decode_access_token(token)
    assert payload["sub"] == "admin1"
    assert payload["role"] == "Admin"


def test_rbac_permissions():
    assert has_permission("Admin", "admin:read") is True
    assert has_permission("User", "admin:read") is False
    assert has_permission("User", "invoices:read") is True


def test_ttl_cache_expiry():
    cache = TTLCache(default_ttl_seconds=0.1)
    cache.set("key1", "val1")
    assert cache.get("key1") == "val1"
    import time
    time.sleep(0.15)
    assert cache.get("key1") is None


def test_app_login_and_admin_endpoint():
    # Reset fault state
    r_reset = client.post("/faults/reset")
    assert r_reset.status_code == 200

    # Login
    r_login = client.post("/auth/login", json={"user_id": "admin1"})
    assert r_login.status_code == 200
    token = r_login.json()["access_token"]

    # Access admin endpoint
    headers = {"Authorization": f"Bearer {token}"}
    r_admin = client.get("/admin/users", headers=headers)
    assert r_admin.status_code == 200
    assert "admin1" in r_admin.json()["users"]


def test_stale_cache_fault_injection():
    # Reset
    client.post("/faults/reset")

    # Login
    r_login = client.post("/auth/login", json={"user_id": "admin1"})
    token = r_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Verify initial access
    assert client.get("/admin/users", headers=headers).status_code == 200

    # Inject stale cache fault (revokes DB role, but retains old role in cache)
    r_fault = client.post("/faults/inject", json={"fault_type": "stale_cache", "user_id": "admin1", "new_role": "User", "cache_ttl_seconds": 2.0})
    assert r_fault.status_code == 200

    # Immediate access post-revocation should STILL be allowed due to stale cache!
    r_post = client.get("/admin/users", headers=headers)
    assert r_post.status_code == 200
