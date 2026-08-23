"""
Fault Injector Client for AuthTime Engine.

Communicates with the reference application's local fault injection interface.
"""

from typing import Optional, Dict, Any
from urllib.parse import urlparse
import httpx
from app.config import settings


class FaultInjectorClient:
    def __init__(self, target_url: Optional[str] = None):
        self.target_url = target_url or f"http://{settings.TARGET_HOST}:{settings.TARGET_PORT}"
        self._enforce_safety_boundary()

    def _enforce_safety_boundary(self):
        """Hardcoded safety guard ensuring target URL is local loopback only."""
        parsed = urlparse(self.target_url)
        hostname = parsed.hostname or ""
        if hostname not in ("127.0.0.1", "localhost", "::1", "testclient"):
            raise ValueError(
                f"SAFETY VIOLATION: FaultInjectorClient target URL '{self.target_url}' "
                f"is not a local loopback address (127.0.0.1 / localhost)."
            )

    async def inject_fault(
        self,
        fault_type: str,
        user_id: str = "admin1",
        new_role: Optional[str] = "User",
        cache_ttl_seconds: Optional[float] = None,
        time_scale_factor: Optional[float] = 1.0,
    ) -> Dict[str, Any]:
        """
        Injects a controlled fault directive via POST /faults/inject.
        """
        self._enforce_safety_boundary()
        endpoint = f"{self.target_url}/faults/inject"
        payload = {
            "fault_type": fault_type,
            "user_id": user_id,
            "new_role": new_role,
            "cache_ttl_seconds": cache_ttl_seconds,
            "time_scale_factor": time_scale_factor,
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(endpoint, json=payload, headers={"X-AuthTime-Request-ID": "fault-inject-req"})
            if resp.status_code != 200:
                raise RuntimeError(f"Fault injection failed: HTTP {resp.status_code} - {resp.text}")
            return resp.json()

    async def reset(self) -> Dict[str, Any]:
        """
        Resets target application state and cache via POST /faults/reset.
        """
        self._enforce_safety_boundary()
        endpoint = f"{self.target_url}/faults/reset"
        async with httpx.AsyncClient() as client:
            resp = await client.post(endpoint, headers={"X-AuthTime-Request-ID": "fault-reset-req"})
            if resp.status_code != 200:
                raise RuntimeError(f"State reset failed: HTTP {resp.status_code} - {resp.text}")
            return resp.json()
