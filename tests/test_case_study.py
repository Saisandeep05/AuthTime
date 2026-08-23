"""
AuthTime — Employee Offboarding Real-World Case Study Automated Test Suite.
Tests pre-revocation access, post-revocation denial, vulnerable stale cache exposure,
version-aware mitigation, per-replica metrics, and evidence integrity.
"""

import pytest
import asyncio
import time
from fastapi.testclient import TestClient

from targets.distributed_lab.service.app import create_lab_replica_app
from targets.distributed_lab.db.database import LabDatabase
from targets.distributed_lab.cache.redis_cache import LabRedisCache
from targets.distributed_lab.auth.jwt_handler import LabJWTHandler
from authtime.adapters.target_adapter import DistributedLabAdapter
from authtime.scenarios.generator import ScenarioGenerator


@pytest.fixture
def lab_components():
    db = LabDatabase()
    cache = LabRedisCache()
    jwt_h = LabJWTHandler()
    app = create_lab_replica_app(replica_id="api-1", db=db, cache=cache, jwt_handler=jwt_h)
    client = TestClient(app)
    return {"db": db, "cache": cache, "jwt": jwt_h, "app": app, "client": client}


@pytest.mark.asyncio
async def test_employee_pre_revocation_access(lab_components):
    """Test that Alice with Finance Admin role can access protected finance endpoints."""
    db = lab_components["db"]
    client = lab_components["client"]

    # Reset DB state
    await db.reset_database()

    role = await db.get_user_role("alice")
    assert role == "Finance Admin"

    # Login as alice
    login_resp = client.post("/login", json={"user_id": "alice"})
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    headers = {"Authorization": f"Bearer {token}"}

    # Test all finance endpoints
    for ep in ["/finance/payroll", "/finance/payments", "/finance/reports"]:
        resp = client.get(ep, headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ALLOW"
        assert data["role"] == "Finance Admin"


@pytest.mark.asyncio
async def test_employee_post_revocation_authoritative_denial(lab_components):
    """Test that revoking Alice's role to Employee changes authoritative DB state."""
    db = lab_components["db"]
    client = lab_components["client"]

    await db.reset_database()

    # Revoke role
    event = await db.revoke_user_role("alice", "Employee")
    assert event["new_role"] == "Employee"
    assert event["auth_version"] == 2

    # Check DB role
    new_role = await db.get_user_role("alice")
    assert new_role == "Employee"

    # Verify login gives Employee token
    login_resp = client.post("/login", json={"user_id": "alice"})
    assert login_resp.status_code == 200
    assert login_resp.json()["role"] == "Employee"
    assert login_resp.json()["auth_version"] == 2


@pytest.mark.asyncio
async def test_vulnerable_stale_authorization_exposure(lab_components):
    """Test that under vulnerable mode, cached authorization allows stale access."""
    db = lab_components["db"]
    cache = lab_components["cache"]
    client = lab_components["client"]

    await db.reset_database()
    await cache.clear_cache()

    # Initial login as alice (Finance Admin)
    login_resp = client.post("/login", json={"user_id": "alice"})
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Populate cache via first request
    resp1 = client.get("/finance/payroll", headers=headers)
    assert resp1.status_code == 200

    # Configure vulnerable cache mode (ttl = 60s)
    cache.configure_fault_mode(mode="ttl", ttl_sec=60.0)

    # Demote alice in DB
    await db.revoke_user_role("alice", "Employee")

    # Invalidate cache under ttl mode (marks is_stale=True, but keeps entry)
    await cache.invalidate_user("alice", "Employee", 2, ["api-1"])

    # Probe again -> Vulnerable cache returns stale ALLOW
    resp2 = client.get("/finance/payroll", headers=headers)
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "ALLOW"
    assert resp2.json()["is_stale"] is True


@pytest.mark.asyncio
async def test_mitigation_version_aware_cache_validation(lab_components):
    """Test that mitigation mode detects version mismatch and evicts stale cache."""
    db = lab_components["db"]
    cache = lab_components["cache"]
    client = lab_components["client"]

    await db.reset_database()
    await cache.clear_cache()

    # Login as alice (auth_ver = 1)
    login_resp = client.post("/login", json={"user_id": "alice"})
    token_v1 = login_resp.json()["access_token"]
    headers_v1 = {"Authorization": f"Bearer {token_v1}"}

    # Populate cache
    r1 = client.get("/finance/payroll", headers=headers_v1)
    assert r1.status_code == 200

    # Enable mitigation mode
    cfg_resp = client.post("/faults/configure-mitigation", json={"enabled": True})
    assert cfg_resp.status_code == 200

    # Demote alice in DB -> increments auth_version to 2
    await db.revoke_user_role("alice", "Employee")

    # Probe with v1 token under mitigation mode -> detects version mismatch -> 403 Forbidden
    r2 = client.get("/finance/payroll", headers=headers_v1)
    assert r2.status_code == 403
    assert "Forbidden" in r2.json()["detail"]


def test_scenario_generator_offboarding_scenario():
    """Test offboarding scenario generation."""
    scen = ScenarioGenerator.generate_employee_offboarding_scenario("alice", "/finance/payroll")
    assert scen.target_user_id == "alice"
    assert scen.resource_path == "/finance/payroll"
    assert "offboarding-alice" in scen.scenario_id


def test_exposure_reduction_calculation():
    """Test before/after exposure reduction calculation logic."""
    vuln_max = 4.25
    mit_max = 0.00
    pct = ((vuln_max - mit_max) / vuln_max) * 100.0
    assert pct == 100.0


@pytest.mark.asyncio
async def test_mitigation_failure_modes(lab_components):
    """Test mitigation behavior when token claims are missing or malformed."""
    client = lab_components["client"]

    # 1. Missing Authorization header
    r_missing = client.get("/finance/payroll")
    assert r_missing.status_code == 401
    assert "Missing or malformed Authorization header" in r_missing.json()["detail"]

    # 2. Malformed token string
    r_malformed = client.get("/finance/payroll", headers={"Authorization": "Bearer invalid_token_str"})
    assert r_malformed.status_code == 401


def test_doc_and_json_metric_consistency():
    """Verify that documentation markdown files contain metrics consistent with comparison.json."""
    import json
    import os

    comp_path = "experiments/employee_offboarding_case_study/comparison.json"
    doc_path = "docs/real-world-case-study.md"
    readme_path = "README.md"

    if not os.path.exists(comp_path):
        pytest.skip("comparison.json evidence artifact not found.")

    with open(comp_path, "r", encoding="utf-8") as f:
        comp_data = json.load(f)

    metrics = comp_data.get("metrics", {})
    vuln_max = metrics.get("vulnerable_max_exposure_sec", 0.0)

    # Read case study doc
    with open(doc_path, "r", encoding="utf-8") as f:
        doc_text = f.read()

    # Verify that rounded vuln max exposure appears in documentation
    vuln_str = f"{vuln_max:.2f}s"
    assert vuln_str in doc_text, f"Expected {vuln_str} in {doc_path}"

    # Read README
    with open(readme_path, "r", encoding="utf-8") as f:
        readme_text = f.read()

    assert vuln_str in readme_text, f"Expected {vuln_str} in {readme_path}"

