"""
AuthTime Distributed Lab - Dedicated Level C Infrastructure Test Suite.
Tests real PostgreSQL, Redis, and multi-replica process connectivity and revocation propagation.
Strictly fails or skips with clear diagnostic messages if infrastructure daemons are absent.
"""

import os
import socket
import pytest
import httpx
import asyncio

POSTGRES_HOST = os.getenv("POSTGRES_HOST", "127.0.0.1")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_DSN = os.getenv("POSTGRES_DSN", f"postgresql://authtime:authtime123@{POSTGRES_HOST}:{POSTGRES_PORT}/authtimedb")

REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

REPLICA_PORTS = [8010, 8011, 8012]


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ConnectionRefusedError):
        return False


@pytest.mark.asyncio
async def test_postgresql_authoritative_connection_and_revocation():
    """Verifies direct PostgreSQL connectivity, schema initialization, role update, and revocation."""
    if not is_port_open(POSTGRES_HOST, POSTGRES_PORT):
        pytest.skip(
            f"Level C Infrastructure Test SKIPPED: PostgreSQL is not reachable on {POSTGRES_HOST}:{POSTGRES_PORT}. "
            "Start the Docker Compose lab ('docker compose -f docker-compose.lab.yml up -d') to run Level C tests."
        )

    try:
        import asyncpg
    except ImportError:
        pytest.fail("Level C Infrastructure Test FAILED: 'asyncpg' library is required for PostgreSQL integration.")

    conn = await asyncpg.connect(POSTGRES_DSN)
    try:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id VARCHAR(64) PRIMARY KEY,
                role VARCHAR(32) NOT NULL,
                auth_version INT NOT NULL DEFAULT 1,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        """)
        await conn.execute("""
            INSERT INTO users (user_id, role, auth_version)
            VALUES ('alice_infra_test', 'Finance Admin', 1)
            ON CONFLICT (user_id) DO UPDATE SET role = 'Finance Admin', auth_version = 1;
        """)

        role_before = await conn.fetchval("SELECT role FROM users WHERE user_id = $1", 'alice_infra_test')
        assert role_before == 'Finance Admin'

        await conn.execute("UPDATE users SET role = 'User', auth_version = auth_version + 1 WHERE user_id = $1", 'alice_infra_test')
        role_after = await conn.fetchval("SELECT role FROM users WHERE user_id = $1", 'alice_infra_test')
        assert role_after == 'User'

    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_redis_authoritative_connection_and_invalidation():
    """Verifies direct Redis connectivity, PING response, string caching, and pub/sub invalidation."""
    if not is_port_open(REDIS_HOST, REDIS_PORT):
        pytest.skip(
            f"Level C Infrastructure Test SKIPPED: Redis is not reachable on {REDIS_HOST}:{REDIS_PORT}. "
            "Start the Docker Compose lab ('docker compose -f docker-compose.lab.yml up -d') to run Level C tests."
        )

    try:
        import redis.asyncio as aioredis
    except ImportError:
        pytest.fail("Level C Infrastructure Test FAILED: 'redis' library is required for Redis integration.")

    r = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    try:
        pong = await r.ping()
        assert pong is True or pong == "PONG"

        await r.set("auth:alice_infra_test", "Finance Admin", ex=60)
        cached_role = await r.get("auth:alice_infra_test")
        assert cached_role == "Finance Admin"

        pubsub = r.pubsub()
        await pubsub.subscribe("auth_invalidations")

        await r.publish("auth_invalidations", "alice_infra_test")
        message = None
        for _ in range(5):
            msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if msg and msg.get("data") == "alice_infra_test":
                message = msg
                break
            await asyncio.sleep(0.1)

        assert message is not None
        assert message["data"] == "alice_infra_test"

        await pubsub.unsubscribe("auth_invalidations")
    finally:
        await r.close()


@pytest.mark.asyncio
async def test_three_replica_processes_and_identity():
    """Verifies three independent API processes are running and return distinct replica identities."""
    open_ports = [port for port in REPLICA_PORTS if is_port_open("127.0.0.1", port)]
    if len(open_ports) < 3:
        pytest.skip(
            f"Level C Infrastructure Test SKIPPED: Only {len(open_ports)} of 3 replica ports ({REPLICA_PORTS}) are reachable. "
            "Start the Docker Compose lab ('docker compose -f docker-compose.lab.yml up -d') to run Level C tests."
        )

    async with httpx.AsyncClient(timeout=3.0) as client:
        replica_ids = set()
        for port in REPLICA_PORTS:
            res = await client.get(f"http://127.0.0.1:{port}/")
            assert res.status_code == 200
            data = res.json()
            assert "replica_id" in data
            replica_ids.add(data["replica_id"])

        assert len(replica_ids) == 3, f"Expected 3 distinct replica identities, got {replica_ids}"
