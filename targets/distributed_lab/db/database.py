"""
AuthTime Distributed Lab - Database Abstraction Layer.
Delegates to AuthorizationStateStore supporting real PostgreSQL (Level C) or thread-safe in-memory store (Level B).
"""

import os
from typing import Dict, Any, Optional, List
from targets.distributed_lab.db.store import (
    AuthorizationStateStore,
    InMemoryAuthorizationStateStore,
    PostgreSQLAuthorizationStateStore,
)


class LabDatabase:
    """
    Authoritative Authorization Source of Truth Database.
    Manages users, roles, authorization versions, and revocation events.
    """

    def __init__(self, dsn: Optional[str] = None):
        self.dsn = dsn or os.getenv("POSTGRES_DSN", "postgresql://authtime:authtime123@127.0.0.1:5432/authtimedb")
        self._pg_store = PostgreSQLAuthorizationStateStore(self.dsn)
        self._mem_store = InMemoryAuthorizationStateStore()
        self._active_store: AuthorizationStateStore = self._mem_store

    async def initialize(self) -> None:
        """Initialize database connections and table schemas."""
        await self._pg_store.initialize()
        if self._pg_store._is_connected:
            self._active_store = self._pg_store
        else:
            self._active_store = self._mem_store
            await self._mem_store.initialize()

    async def get_user_role(self, user_id: str) -> str:
        """Fetch current authoritative user role."""
        return await self._active_store.get_user_role(user_id)

    async def get_auth_version(self, user_id: str) -> int:
        """Fetch current authorization version for token invalidation."""
        return await self._active_store.get_auth_version(user_id)

    async def revoke_user_role(self, user_id: str, new_role: str = "User") -> Dict[str, Any]:
        """
        Revoke or demote user role in authoritative database.
        Returns the created revocation event with authoritative timestamp t0.
        """
        return await self._active_store.revoke_user_role(user_id, new_role)

    async def get_revocation_events(self) -> List[Dict[str, Any]]:
        """Fetch immutable history of revocation events."""
        return await self._active_store.get_revocation_events()

    async def reset_database(self) -> None:
        """Reset database state to initial baseline."""
        await self._active_store.reset_database()
