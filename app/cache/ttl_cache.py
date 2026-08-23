"""
Extensible Thread-Safe In-Memory Authorization TTL Cache.
"""

import time
import threading
from typing import Dict, Any, Optional, Tuple


class AuthCache:
    def __init__(self, default_ttl_seconds: float = 60.0):
        self._cache: Dict[str, Tuple[Any, float]] = {}  # key -> (data, expire_at)
        self.default_ttl = default_ttl_seconds
        self._lock = threading.RLock()
        self.enabled = True

    def get(self, key: str) -> Tuple[Optional[Any], bool]:
        """
        Returns (cached_value, cache_hit).
        If entry exists and is valid (or staleness is enforced), returns data.
        """
        if not self.enabled:
            return None, False

        with self._lock:
            if key not in self._cache:
                return None, False

            data, expire_at = self._cache[key]
            now = time.monotonic()
            if now > expire_at:
                del self._cache[key]
                return None, False

            return data, True

    def set(self, key: str, value: Any, ttl_seconds: Optional[float] = None) -> None:
        if not self.enabled:
            return

        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        with self._lock:
            expire_at = time.monotonic() + ttl
            self._cache[key] = (value, expire_at)

    def invalidate(self, key: str) -> bool:
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def set_stale(self, key: str, stale_value: Any, extend_seconds: float = 60.0) -> None:
        """Controlled fault helper to force stale cache retention."""
        with self._lock:
            expire_at = time.monotonic() + extend_seconds
            self._cache[key] = (stale_value, expire_at)


# Shared singleton cache instance
auth_cache = AuthCache()
