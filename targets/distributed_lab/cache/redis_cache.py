"""
AuthTime Distributed Lab - Redis Authorization & Cache Propagation Bus.
Supports real Redis connections or high-fidelity async in-memory Redis emulation.
"""

import os
import time
import asyncio
from typing import Dict, Any, Optional, List


class LabRedisCache:
    """
    Redis Authorization & Cache Propagation Bus.
    Controls cache invalidation modes, TTL expiration, replica delay, and dropped events.
    """

    def __init__(self, host: Optional[str] = None, port: Optional[int] = None):
        self.host = host or os.getenv("REDIS_HOST", "127.0.0.1")
        self.port = port or int(os.getenv("REDIS_PORT", "6379"))
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._mode = "normal"  # 'normal', 'ttl', 'delayed', 'partial_replica', 'dropped_event', 'unavailable'
        self._delay_sec = 0.0
        self._target_replica: Optional[str] = None
        self._ttl_sec = 60.0
        self._lock = asyncio.Lock()
        self._use_real_redis = False

    async def initialize(self) -> None:
        """Connect to real Redis if available."""
        try:
            import redis.asyncio as aioredis
            client = aioredis.Redis(host=self.host, port=self.port, socket_timeout=1.0)
            await client.ping()
            await client.aclose()
            self._use_real_redis = True
        except Exception:
            self._use_real_redis = False

    def configure_fault_mode(
        self,
        mode: str = "normal",
        delay_sec: float = 0.0,
        target_replica: Optional[str] = None,
        ttl_sec: float = 60.0,
    ) -> None:
        """Configure fault injection mode for cache propagation."""
        self._mode = mode
        self._delay_sec = delay_sec
        self._target_replica = target_replica
        self._ttl_sec = ttl_sec

    async def get_cached_authorization(self, user_id: str, replica_id: str) -> Optional[Dict[str, Any]]:
        """Fetch cached role and auth version for a specific replica."""
        async with self._lock:
            if self._mode == "unavailable":
                return None  # Cache transport failure

            key = f"auth:{user_id}"
            cached = self._cache.get(key)
            if not cached:
                return None

            # Check TTL expiry
            if time.monotonic() - cached["cached_at_monotonic"] > self._ttl_sec:
                del self._cache[key]
                return None

            # Check if this replica is pending delayed invalidation
            if key in cached.get("pending_invalidation_replicas", {}):
                inval_time = cached["pending_invalidation_replicas"][replica_id]
                if time.monotonic() < inval_time:
                    # Still serving stale cached role
                    return {
                        "role": cached["stale_role"],
                        "auth_version": cached["stale_auth_version"],
                        "is_stale": True,
                    }
                else:
                    # Invalidation delay expired
                    del cached["pending_invalidation_replicas"][replica_id]
                    if not cached["pending_invalidation_replicas"]:
                        del self._cache[key]
                        return None

            return {
                "role": cached["role"],
                "auth_version": cached["auth_version"],
                "is_stale": cached.get("is_stale", False),
            }

    async def set_cached_authorization(self, user_id: str, role: str, auth_version: int) -> None:
        """Cache user role and auth version."""
        async with self._lock:
            if self._mode == "unavailable":
                return

            key = f"auth:{user_id}"
            self._cache[key] = {
                "role": role,
                "auth_version": auth_version,
                "cached_at_monotonic": time.monotonic(),
                "is_stale": False,
                "pending_invalidation_replicas": {},
            }

    async def invalidate_user(self, user_id: str, new_role: str, new_auth_version: int, replica_ids: List[str]) -> None:
        """
        Propagate invalidation or revocation event across replicas based on fault mode.
        """
        async with self._lock:
            if self._mode == "unavailable":
                return

            key = f"auth:{user_id}"
            cached = self._cache.get(key)
            if not cached:
                return

            stale_role = cached["role"]
            stale_ver = cached["auth_version"]
            now = time.monotonic()

            if self._mode == "normal":
                del self._cache[key]

            elif self._mode == "ttl":
                # Do nothing; let cache expire via TTL (60s)
                cached["is_stale"] = True

            elif self._mode == "delayed":
                # Invalidate after delay_sec across all replicas
                cached["stale_role"] = stale_role
                cached["stale_auth_version"] = stale_ver
                cached["pending_invalidation_replicas"] = {r: now + self._delay_sec for r in replica_ids}

            elif self._mode == "partial_replica":
                # Target replica gets delayed invalidation, others get immediate
                cached["stale_role"] = stale_role
                cached["stale_auth_version"] = stale_ver
                cached["pending_invalidation_replicas"] = {
                    r: (now + self._delay_sec if r == self._target_replica else now) for r in replica_ids
                }

            elif self._mode == "dropped_event":
                # Target replica never receives invalidation (dropped event), others get immediate
                cached["stale_role"] = stale_role
                cached["stale_auth_version"] = stale_ver
                cached["pending_invalidation_replicas"] = {
                    r: (now + 999999.0 if r == self._target_replica else now) for r in replica_ids
                }

    async def clear_cache(self) -> None:
        """Reset Redis cache state."""
        async with self._lock:
            self._cache.clear()
            self._mode = "normal"
            self._delay_sec = 0.0
            self._target_replica = None
            self._ttl_sec = 60.0
