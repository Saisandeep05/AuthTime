"""
Integration Tests for AuthTime Distributed Authorization Laboratory.
Tests multi-replica HTTP probing, role revocation propagation, and fault injection.
"""

import pytest
import httpx
from targets.distributed_lab.db.database import LabDatabase
from targets.distributed_lab.cache.redis_cache import LabRedisCache
from targets.distributed_lab.auth.jwt_handler import LabJWTHandler
from targets.distributed_lab.service.app import create_lab_replica_app


@pytest.mark.asyncio
async def test_multi_replica_identity_and_auth_flow():
    db = LabDatabase()
    cache = LabRedisCache()
    jwt_h = LabJWTHandler()

    await db.initialize()
    await cache.initialize()

    # Create 3 replica apps
    app1 = create_lab_replica_app("api-1", db, cache, jwt_h)
    app2 = create_lab_replica_app("api-2", db, cache, jwt_h)
    app3 = create_lab_replica_app("api-3", db, cache, jwt_h)

    transport1 = httpx.ASGITransport(app=app1)
    transport2 = httpx.ASGITransport(app=app2)
    transport3 = httpx.ASGITransport(app=app3)

    async with httpx.AsyncClient(transport=transport1, base_url="http://api-1") as client1, \
               httpx.AsyncClient(transport=transport2, base_url="http://api-2") as client2, \
               httpx.AsyncClient(transport=transport3, base_url="http://api-3") as client3:

        # 1. Identity handshake
        id1 = (await client1.get("/identity")).json()
        id2 = (await client2.get("/identity")).json()
        id3 = (await client3.get("/identity")).json()

        assert id1["replica_id"] == "api-1"
        assert id2["replica_id"] == "api-2"
        assert id3["replica_id"] == "api-3"

        # 2. Login on api-1
        login_resp = await client1.post("/login", json={"user_id": "admin1"})
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]

        headers = {"Authorization": f"Bearer {token}"}

        # 3. Access admin route on all 3 replicas -> all 200 ALLOW
        r1 = await client1.get("/admin/users", headers=headers)
        r2 = await client2.get("/admin/users", headers=headers)
        r3 = await client3.get("/admin/users", headers=headers)

        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r3.status_code == 200

        # 4. Inject role revocation on api-1 in normal mode
        revoke_resp = await client1.post("/faults/revoke", json={"user_id": "admin1", "new_role": "User"})
        assert revoke_resp.status_code == 200

        # 5. Access admin route on all replicas -> immediate 403 DENY
        r1_after = await client1.get("/admin/users", headers=headers)
        r2_after = await client2.get("/admin/users", headers=headers)
        r3_after = await client3.get("/admin/users", headers=headers)

        assert r1_after.status_code == 403
        assert r2_after.status_code == 403
        assert r3_after.status_code == 403


@pytest.mark.asyncio
async def test_partial_replica_propagation_fault_injection():
    db = LabDatabase()
    cache = LabRedisCache()
    jwt_h = LabJWTHandler()

    await db.initialize()
    await cache.initialize()

    app1 = create_lab_replica_app("api-1", db, cache, jwt_h)
    app2 = create_lab_replica_app("api-2", db, cache, jwt_h)

    transport1 = httpx.ASGITransport(app=app1)
    transport2 = httpx.ASGITransport(app=app2)

    async with httpx.AsyncClient(transport=transport1, base_url="http://api-1") as client1, \
               httpx.AsyncClient(transport=transport2, base_url="http://api-2") as client2:

        # Reset state
        await client1.post("/reset")

        # Login
        token = (await client1.post("/login", json={"user_id": "admin1"})).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Prime cache on both replicas
        await client1.get("/admin/users", headers=headers)
        await client2.get("/admin/users", headers=headers)

        # Configure partial replica propagation (api-2 delayed by 5.0s)
        await client1.post(
            "/faults/configure-cache-mode",
            json={"mode": "partial_replica", "delay_sec": 5.0, "target_replica": "api-2"},
        )

        # Inject revocation
        await client1.post("/faults/revoke", json={"user_id": "admin1", "new_role": "User"})

        # api-1 immediately revokes -> 403 DENY
        r1 = await client1.get("/admin/users", headers=headers)
        assert r1.status_code == 403

        # api-2 serves stale cache -> 200 ALLOW (vulnerable exposure!)
        r2 = await client2.get("/admin/users", headers=headers)
        assert r2.status_code == 200
        assert r2.json()["is_stale"] is True
