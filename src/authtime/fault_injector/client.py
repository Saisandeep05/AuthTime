"""
Fault Injector Client.

Issues controlled fault injection directives to the reference target application via HTTP.
"""

from typing import Dict, Any, Optional
from urllib.parse import urlparse
import httpx


class FaultInjectorClient:
    def __init__(self, target_url: str = "http://127.0.0.1:8000", http_client: Optional[httpx.AsyncClient] = None):
        self.target_url = target_url.rstrip("/")
        self._enforce_safety_boundary()
        self._shared_client = http_client

    def _enforce_safety_boundary(self):
        parsed = urlparse(self.target_url)
        hostname = parsed.hostname or ""
        if hostname not in ("127.0.0.1", "localhost", "::1", "testclient"):
            raise ValueError(
                f"SAFETY VIOLATION: Target URL '{self.target_url}' is non-local! "
                f"AuthTime testing is restricted exclusively to 127.0.0.1 / localhost."
            )

    async def inject_fault(
        self,
        fault_type: str,
        user_id: str,
        secondary_user_id: Optional[str] = None,
        new_role: str = "User",
        cache_ttl_seconds: float = 60.0,
        time_scale_factor: float = 1.0,
        experiment_id: Optional[str] = None,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> Dict[str, Any]:
        self._enforce_safety_boundary()
        close_client = False
        client = http_client or self._shared_client
        if client is None:
            client = httpx.AsyncClient()
            close_client = True

        try:
            payload = {
                "fault_type": fault_type,
                "user_id": user_id,
                "secondary_user_id": secondary_user_id,
                "new_role": new_role,
                "cache_ttl_seconds": cache_ttl_seconds,
                "time_scale_factor": time_scale_factor,
                "experiment_id": experiment_id,
            }

            req_id = f"fault-{experiment_id}-{fault_type}" if experiment_id else f"fault-{fault_type}"
            headers = {"X-AuthTime-Request-ID": req_id}
            if experiment_id:
                headers["X-AuthTime-Experiment-ID"] = experiment_id
                headers["X-AuthTime-Trial-ID"] = f"{experiment_id}-trial"

            resp = await client.post(
                f"{self.target_url}/faults/inject",
                json=payload,
                headers=headers,
            )

            if resp.status_code != 200:
                raise RuntimeError(f"Fault injection failed with status {resp.status_code}: {resp.text}")
            return resp.json()

        finally:
            if close_client and client:
                await client.aclose()

    async def reset(self, http_client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
        self._enforce_safety_boundary()
        close_client = False
        client = http_client or self._shared_client
        if client is None:
            client = httpx.AsyncClient()
            close_client = True

        try:
            resp = await client.post(
                f"{self.target_url}/faults/reset",
                headers={"X-AuthTime-Request-ID": "fault-reset"},
            )
            if resp.status_code != 200:
                raise RuntimeError(f"Reset failed with status {resp.status_code}")
            return resp.json()
        finally:
            if close_client and client:
                await client.aclose()
