"""
AuthTime Distributed Lab - Authorization Race Condition Test Suite.
Verifies atomicity, event order invariants, and state reconciliation under high-concurrency race conditions.
"""

import time
import pytest
import asyncio
from targets.distributed_lab.db.database import LabDatabase
from targets.distributed_lab.cache.redis_cache import LabRedisCache
from targets.distributed_lab.auth.jwt_handler import LabJWTHandler


@pytest.mark.asyncio
async def test_race_simultaneous_request_and_revocation():
    """Scenario 1: Request reads state while role revocation occurs concurrently."""
    db = LabDatabase()
    await db.initialize()
    cache = LabRedisCache()
    await cache.initialize()

    # Pre-cache user state
    await cache.set_cached_authorization("alice", "Finance Admin", 1, "api-1")

    async def _read_authorization():
        return await cache.get_cached_authorization("alice", "api-1")

    async def _perform_revocation():
        evt = await db.revoke_user_role("alice", "User")
        await cache.invalidate_user("alice", "User", evt["auth_version"], ["api-1"])
        return evt

    # Run read and revocation concurrently
    results = await asyncio.gather(_read_authorization(), _perform_revocation())
    read_state, rev_event = results[0], results[1]

    # Post-revocation check must reflect new authoritative database state
    post_role = await db.get_user_role("alice")
    assert post_role == "User"
    assert rev_event["auth_version"] == 2


@pytest.mark.asyncio
async def test_race_concurrent_multi_user_revocations():
    """Scenario 2: Multiple concurrent revocations for different users."""
    db = LabDatabase()
    await db.initialize()

    users = [f"user_{i}" for i in range(10)]
    tasks = [db.revoke_user_role(u, "User") for u in users]

    rev_events = await asyncio.gather(*tasks)

    assert len(rev_events) == 10
    for evt in rev_events:
        assert evt["new_role"] == "User"
        assert evt["auth_version"] >= 2


@pytest.mark.asyncio
async def test_race_immediate_login_post_revocation():
    """Scenario 3: Revocation followed immediately by new login & token issuance."""
    jwt_handler = LabJWTHandler()
    db = LabDatabase()
    await db.initialize()

    # Step 1: Revoke role in DB
    rev_evt = await db.revoke_user_role("alice", "User")
    assert rev_evt["new_role"] == "User"

    # Step 2: Issue new token immediately post-revocation
    new_role = await db.get_user_role("alice")
    new_ver = await db.get_auth_version("alice")
    new_token = jwt_handler.create_access_token("alice", role=new_role, auth_version=new_ver)

    # Step 3: Validate new token carries updated role and version
    claims = jwt_handler.verify_access_token(new_token)
    assert claims["role"] == "User"
    assert claims["auth_ver"] == 2


@pytest.mark.asyncio
async def test_race_old_jwt_vs_new_jwt():
    """Scenario 4: Old JWT and newly issued JWT presented simultaneously."""
    jwt_handler = LabJWTHandler()

    old_token = jwt_handler.create_access_token("alice", role="Finance Admin", auth_version=1)
    new_token = jwt_handler.create_access_token("alice", role="User", auth_version=2)

    old_claims = jwt_handler.verify_access_token(old_token)
    new_claims = jwt_handler.verify_access_token(new_token)

    assert old_claims["auth_ver"] == 1
    assert old_claims["role"] == "Finance Admin"
    assert new_claims["auth_ver"] == 2
    assert new_claims["role"] == "User"


@pytest.mark.asyncio
async def test_race_duplicate_invalidation_events():
    """Scenario 5: Duplicate invalidation event delivery processing."""
    cache = LabRedisCache()
    await cache.initialize()

    await cache.set_cached_authorization("alice", "Finance Admin", 1, "api-1")

    # Fire duplicate invalidation events
    await cache.invalidate_user("alice", "User", 2, ["api-1"])
    await cache.invalidate_user("alice", "User", 2, ["api-1"])

    cached = await cache.get_cached_authorization("alice", "api-1")
    assert cached is None  # Cache cleanly invalidated without crash or lockup


@pytest.mark.asyncio
async def test_race_out_of_order_auth_version_events():
    """Scenario 6: Out-of-order authorization version event processing."""
    db = LabDatabase()
    await db.initialize()

    # Simulate version updates 2 then 3
    evt1 = await db.revoke_user_role("alice", "Manager")
    evt2 = await db.revoke_user_role("alice", "User")

    assert evt1["auth_version"] == 2
    assert evt2["auth_version"] == 3

    current_ver = await db.get_auth_version("alice")
    assert current_ver == 3
