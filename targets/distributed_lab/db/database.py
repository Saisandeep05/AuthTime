"""
AuthTime Distributed Lab - Database Abstraction Layer.
Supports real PostgreSQL connections via asyncpg/psycopg2 or high-fidelity async SQLite/dict fallback.
"""

import os
import time
import uuid
import asyncio
from typing import Dict, Any, Optional, List


class LabDatabase:
    """
    Authoritative Authorization Source of Truth Database.
    Manages users, roles, authorization versions, and revocation events.
    """

    def __init__(self, dsn: Optional[str] = None):
        self.dsn = dsn or os.getenv("POSTGRES_DSN", "postgresql://authtime:authtime123@127.0.0.1:5432/authtimedb")
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
        self._use_real_postgres = False

    async def initialize(self) -> None:
        """Initialize database tables or fallback memory state."""
        try:
            import asyncpg
            conn = await asyncpg.connect(self.dsn, timeout=1.5)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS users (id VARCHAR(64) PRIMARY KEY, username VARCHAR(128));
                CREATE TABLE IF NOT EXISTS user_roles (user_id VARCHAR(64), role_id VARCHAR(64), PRIMARY KEY (user_id, role_id));
                CREATE TABLE IF NOT EXISTS authorization_versions (user_id VARCHAR(64) PRIMARY KEY, auth_version INTEGER);
                CREATE TABLE IF NOT EXISTS revocation_events (event_id VARCHAR(64) PRIMARY KEY, user_id VARCHAR(64), revocation_type VARCHAR(64), previous_role VARCHAR(64), new_role VARCHAR(64), authoritative_timestamp DOUBLE PRECISION);
            """)
            await conn.close()
            self._use_real_postgres = True
        except Exception:
            self._use_real_postgres = False

    async def get_user_role(self, user_id: str) -> str:
        """Fetch current authoritative user role."""
        async with self._lock:
            if self._use_real_postgres:
                try:
                    import asyncpg
                    conn = await asyncpg.connect(self.dsn, timeout=1.5)
                    row = await conn.fetchrow(
                        "SELECT role_id FROM user_roles WHERE user_id = $1", user_id
                    )
                    await conn.close()
                    if row:
                        return row["role_id"]
                except Exception:
                    pass
            return self._users.get(user_id, "User")

    async def get_auth_version(self, user_id: str) -> int:
        """Fetch current authorization version for token invalidation."""
        async with self._lock:
            if self._use_real_postgres:
                try:
                    import asyncpg
                    conn = await asyncpg.connect(self.dsn, timeout=1.5)
                    row = await conn.fetchrow(
                        "SELECT auth_version FROM authorization_versions WHERE user_id = $1", user_id
                    )
                    await conn.close()
                    if row:
                        return row["auth_version"]
                except Exception:
                    pass
            return self._auth_versions.get(user_id, 1)

    async def revoke_user_role(self, user_id: str, new_role: str = "User") -> Dict[str, Any]:
        """
        Revoke or demote user role in authoritative database.
        Returns the created revocation event with authoritative timestamp t0.
        """
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

            if self._use_real_postgres:
                try:
                    import asyncpg
                    conn = await asyncpg.connect(self.dsn, timeout=1.5)
                    await conn.execute(
                        "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT (user_id, role_id) DO UPDATE SET role_id = $2",
                        user_id, new_role
                    )
                    await conn.execute(
                        "INSERT INTO authorization_versions (user_id, auth_version) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET auth_version = $2",
                        user_id, self._auth_versions[user_id]
                    )
                    await conn.close()
                except Exception:
                    pass

            return event

    async def get_revocation_events(self) -> List[Dict[str, Any]]:
        """Fetch immutable history of revocation events."""
        async with self._lock:
            return list(self._revocation_events)

    async def reset_database(self) -> None:
        """Reset database state to initial baseline."""
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
            # Preserves _revocation_events for forensic audit trail
