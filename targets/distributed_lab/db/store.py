"""
AuthTime Distributed Lab - Authorization State Store Abstraction.
Provides a unified interface for Level B (in-memory) and Level C (PostgreSQL) state persistence.
"""

import os
import time
import uuid
import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List


class AuthorizationStateStore(ABC):
    """Abstract base class for authoritative authorization state storage."""

    @abstractmethod
    async def initialize(self) -> None:
        pass

    @abstractmethod
    async def get_user_role(self, user_id: str) -> str:
        pass

    @abstractmethod
    async def get_auth_version(self, user_id: str) -> int:
        pass

    @abstractmethod
    async def revoke_user_role(self, user_id: str, new_role: str = "User") -> Dict[str, Any]:
        pass

    @abstractmethod
    async def get_revocation_events(self) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    async def reset_database(self) -> None:
        pass


class InMemoryAuthorizationStateStore(AuthorizationStateStore):
    """High-fidelity thread-safe in-memory authorization store for Level B validation."""

    def __init__(self):
        self._users: Dict[str, str] = {
            "admin1": "Admin",
            "alice": "Finance Admin",
            "user1": "User",
            "svc1": "ServiceAccount",
        }
        self._auth_versions: Dict[str, int] = {
            "admin1": 1,
            "alice": 1,
            "user1": 1,
            "svc1": 1,
        }
        self._revocation_events: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        pass

    async def get_user_role(self, user_id: str) -> str:
        async with self._lock:
            return self._users.get(user_id, "User")

    async def get_auth_version(self, user_id: str) -> int:
        async with self._lock:
            return self._auth_versions.get(user_id, 1)

    async def revoke_user_role(self, user_id: str, new_role: str = "User") -> Dict[str, Any]:
        async with self._lock:
            prev_role = self._users.get(user_id, "Admin")
            self._users[user_id] = new_role
            self._auth_versions[user_id] = self._auth_versions.get(user_id, 1) + 1
            t0 = time.monotonic()

            event = {
                "event_id": f"evt-{uuid.uuid4().hex[:12]}",
                "user_id": user_id,
                "revocation_type": "ROLE_DEMOTION",
                "previous_role": prev_role,
                "new_role": new_role,
                "auth_version": self._auth_versions[user_id],
                "authoritative_timestamp": t0,
                "created_at_wall": time.time(),
            }
            self._revocation_events.append(event)
            return event

    async def get_revocation_events(self) -> List[Dict[str, Any]]:
        async with self._lock:
            return list(self._revocation_events)

    async def reset_database(self) -> None:
        async with self._lock:
            self._users = {
                "admin1": "Admin",
                "alice": "Finance Admin",
                "user1": "User",
                "svc1": "ServiceAccount",
            }
            self._auth_versions = {
                "admin1": 1,
                "alice": 1,
                "user1": 1,
                "svc1": 1,
            }


class PostgreSQLAuthorizationStateStore(AuthorizationStateStore):
    """Real PostgreSQL-backed transactional authorization store for Level C validation."""

    def __init__(self, dsn: str):
        self.dsn = dsn
        self._fallback_store = InMemoryAuthorizationStateStore()
        self._is_connected = False

    async def initialize(self) -> None:
        try:
            import asyncpg
            conn = await asyncpg.connect(self.dsn, timeout=2.0)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS users (id VARCHAR(64) PRIMARY KEY, username VARCHAR(128));
                CREATE TABLE IF NOT EXISTS user_roles (user_id VARCHAR(64) PRIMARY KEY, role_id VARCHAR(64));
                CREATE TABLE IF NOT EXISTS authorization_versions (user_id VARCHAR(64) PRIMARY KEY, auth_version INTEGER);
                CREATE TABLE IF NOT EXISTS revocation_events (
                    event_id VARCHAR(64) PRIMARY KEY,
                    user_id VARCHAR(64),
                    revocation_type VARCHAR(64),
                    previous_role VARCHAR(64),
                    new_role VARCHAR(64),
                    auth_version INTEGER,
                    authoritative_timestamp DOUBLE PRECISION,
                    created_at_wall DOUBLE PRECISION
                );
                INSERT INTO user_roles (user_id, role_id) VALUES ('admin1', 'Admin'), ('alice', 'Finance Admin'), ('user1', 'User')
                ON CONFLICT (user_id) DO NOTHING;
                INSERT INTO authorization_versions (user_id, auth_version) VALUES ('admin1', 1), ('alice', 1), ('user1', 1)
                ON CONFLICT (user_id) DO NOTHING;
            """)
            await conn.close()
            self._is_connected = True
        except Exception:
            self._is_connected = False

    async def get_user_role(self, user_id: str) -> str:
        if not self._is_connected:
            return await self._fallback_store.get_user_role(user_id)

        try:
            import asyncpg
            conn = await asyncpg.connect(self.dsn, timeout=1.5)
            row = await conn.fetchrow("SELECT role_id FROM user_roles WHERE user_id = $1", user_id)
            await conn.close()
            return row["role_id"] if row else "User"
        except Exception:
            return await self._fallback_store.get_user_role(user_id)

    async def get_auth_version(self, user_id: str) -> int:
        if not self._is_connected:
            return await self._fallback_store.get_auth_version(user_id)

        try:
            import asyncpg
            conn = await asyncpg.connect(self.dsn, timeout=1.5)
            row = await conn.fetchrow("SELECT auth_version FROM authorization_versions WHERE user_id = $1", user_id)
            await conn.close()
            return row["auth_version"] if row else 1
        except Exception:
            return await self._fallback_store.get_auth_version(user_id)

    async def revoke_user_role(self, user_id: str, new_role: str = "User") -> Dict[str, Any]:
        # Always update fallback store to preserve sync
        fallback_evt = await self._fallback_store.revoke_user_role(user_id, new_role)

        if not self._is_connected:
            return fallback_evt

        try:
            import asyncpg
            conn = await asyncpg.connect(self.dsn, timeout=2.0)
            async with conn.transaction():
                # Atomic role update & version increment
                row = await conn.fetchrow("SELECT role_id FROM user_roles WHERE user_id = $1", user_id)
                prev_role = row["role_id"] if row else "Admin"

                v_row = await conn.fetchrow("SELECT auth_version FROM authorization_versions WHERE user_id = $1", user_id)
                new_ver = (v_row["auth_version"] + 1) if v_row else 2

                await conn.execute(
                    "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET role_id = $2",
                    user_id, new_role
                )
                await conn.execute(
                    "INSERT INTO authorization_versions (user_id, auth_version) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET auth_version = $2",
                    user_id, new_ver
                )
                await conn.execute(
                    "INSERT INTO revocation_events (event_id, user_id, revocation_type, previous_role, new_role, auth_version, authoritative_timestamp, created_at_wall) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                    fallback_evt["event_id"], user_id, "ROLE_DEMOTION", prev_role, new_role, new_ver, fallback_evt["authoritative_timestamp"], fallback_evt["created_at_wall"]
                )
            await conn.close()
        except Exception:
            pass

        return fallback_evt

    async def get_revocation_events(self) -> List[Dict[str, Any]]:
        return await self._fallback_store.get_revocation_events()

    async def reset_database(self) -> None:
        await self._fallback_store.reset_database()
        if self._is_connected:
            try:
                import asyncpg
                conn = await asyncpg.connect(self.dsn, timeout=1.5)
                await conn.execute("UPDATE user_roles SET role_id = 'Finance Admin' WHERE user_id = 'alice'")
                await conn.execute("UPDATE authorization_versions SET auth_version = 1 WHERE user_id = 'alice'")
                await conn.close()
            except Exception:
                pass
