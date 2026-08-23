"""
Unit Tests for AuthTime Distributed Authorization Laboratory.
Tests DB operations, Redis cache invalidation modes, JWT lifecycle, and DistributedLabAdapter.
"""

import pytest
import time
import asyncio
from targets.distributed_lab.db.database import LabDatabase
from targets.distributed_lab.cache.redis_cache import LabRedisCache
from targets.distributed_lab.auth.jwt_handler import LabJWTHandler
from src.authtime.adapters.target_adapter import DistributedLabAdapter


@pytest.mark.asyncio
async def test_lab_database_operations():
    db = LabDatabase()
    await db.initialize()

    # Initial state
    role = await db.get_user_role("admin1")
    assert role == "Admin"
    ver = await db.get_auth_version("admin1")
    assert ver == 1

    # Revoke role
    event = await db.revoke_user_role("admin1", "User")
    assert event["user_id"] == "admin1"
    assert event["previous_role"] == "Admin"
    assert event["new_role"] == "User"

    # Verify updated state
    new_role = await db.get_user_role("admin1")
    assert new_role == "User"
    new_ver = await db.get_auth_version("admin1")
    assert new_ver == 2

    # Forensic events history
    events = await db.get_revocation_events()
    assert len(events) >= 1
    assert events[-1]["user_id"] == "admin1"


@pytest.mark.asyncio
async def test_redis_cache_invalidation_modes():
    cache = LabRedisCache()
    await cache.initialize()

    # 1. Normal mode
    await cache.set_cached_authorization("admin1", "Admin", 1)
    res = await cache.get_cached_authorization("admin1", "api-1")
    assert res["role"] == "Admin"

    await cache.invalidate_user("admin1", "User", 2, ["api-1", "api-2", "api-3"])
    res_after = await cache.get_cached_authorization("admin1", "api-1")
    assert res_after is None

    # 2. Delayed mode
    cache.configure_fault_mode(mode="delayed", delay_sec=1.0)
    await cache.set_cached_authorization("admin1", "Admin", 1)
    await cache.invalidate_user("admin1", "User", 2, ["api-1", "api-2", "api-3"])

    # Immediate query -> still stale cached role
    stale_res = await cache.get_cached_authorization("admin1", "api-1")
    assert stale_res["role"] == "Admin"
    assert stale_res["is_stale"] is True

    # 3. Partial replica mode
    cache.configure_fault_mode(mode="partial_replica", delay_sec=2.0, target_replica="api-2")
    await cache.set_cached_authorization("user1", "Admin", 1, replica_id="api-1")
    await cache.set_cached_authorization("user1", "Admin", 1, replica_id="api-2")
    await cache.invalidate_user("user1", "User", 2, ["api-1", "api-2", "api-3"])

    # api-1 gets immediate invalidation
    api1_res = await cache.get_cached_authorization("user1", "api-1")
    assert api1_res is None

    # api-2 gets delayed invalidation
    api2_res = await cache.get_cached_authorization("user1", "api-2")
    assert api2_res["role"] == "Admin"


def test_jwt_handler_lifecycle():
    jwt_handler = LabJWTHandler(secret="test-secret-key-12345")
    token = jwt_handler.create_access_token("admin1", "Admin", auth_version=1, ttl_sec=3600.0)

    assert isinstance(token, str)
    payload = jwt_handler.verify_access_token(token)
    assert payload["sub"] == "admin1"
    assert payload["role"] == "Admin"
    assert payload["auth_ver"] == 1


def test_distributed_lab_adapter_per_replica_exposure_math():
    adapter = DistributedLabAdapter()
    t0 = 100.0

    probe_logs = {
        "api-1": [
            {"timestamp_monotonic": 99.0, "status_code": 200},
            {"timestamp_monotonic": 100.2, "status_code": 200},
            {"timestamp_monotonic": 100.5, "status_code": 403},
        ],
        "api-2": [
            {"timestamp_monotonic": 99.0, "status_code": 200},
            {"timestamp_monotonic": 101.5, "status_code": 200},
            {"timestamp_monotonic": 102.0, "status_code": 403},
        ],
        "api-3": [
            {"timestamp_monotonic": 99.0, "status_code": 200},
            {"timestamp_monotonic": 100.1, "status_code": 403},
        ],
    }

    metrics = adapter.calculate_per_replica_exposure(probe_logs, t0_authoritative=t0)
    assert "api-1" in metrics["per_replica"]
    assert "api-2" in metrics["per_replica"]
    assert "api-3" in metrics["per_replica"]

    assert metrics["per_replica"]["api-1"]["dt_exposure_upper_bound_sec"] == pytest.approx(0.5, abs=0.01)
    assert metrics["per_replica"]["api-2"]["dt_exposure_upper_bound_sec"] == pytest.approx(2.0, abs=0.01)
    assert metrics["aggregate"]["replica_count"] == 3
    assert metrics["aggregate"]["max_exposure_sec"] == pytest.approx(2.0, abs=0.01)
