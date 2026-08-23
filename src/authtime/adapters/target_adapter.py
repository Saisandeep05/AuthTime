"""
Target Adapter Abstraction Layer for AuthTime.
Provides a unified, pluggable interface for communicating with multi-framework targets
(FastAPI, Express.js, Django, OpenID CAEP/SSF) during security verification trials.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Tuple
import httpx


class BaseTargetAdapter(ABC):
    """Abstract Base Class for AuthTime Target Adapters."""

    def __init__(self, target_url: str, http_client: Optional[httpx.AsyncClient] = None):
        self.target_url = target_url.rstrip("/")
        self._shared_client = http_client

    @abstractmethod
    async def verify_identity(self) -> Dict[str, Any]:
        """Queries target identity and validates protocol capabilities."""
        pass

    @abstractmethod
    async def reset_state(self, experiment_id: Optional[str] = None) -> Dict[str, Any]:
        """Resets target user roles and authorization caches while preserving audit logs."""
        pass

    @abstractmethod
    async def login_user(self, user_id: str) -> str:
        """Obtains a valid access token for the given user_id."""
        pass

    @abstractmethod
    async def inject_fault(
        self,
        fault_type: str,
        user_id: str,
        new_role: Optional[str] = "User",
        cache_ttl_seconds: float = 60.0,
        time_scale_factor: float = 1.0,
        experiment_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Injects a controlled authorization fault into the target application."""
        pass

    @abstractmethod
    async def probe_endpoint(
        self,
        resource_path: str,
        token: Optional[str],
        request_id: str,
        experiment_id: Optional[str] = None,
    ) -> Tuple[int, str, float]:
        """
        Fires an HTTP GET probe at resource_path using authorization token.
        Returns tuple of (status_code, response_body_text, response_latency_ms).
        """
        pass

    @abstractmethod
    async def fetch_evidence_events(self, experiment_id: str) -> List[Dict[str, Any]]:
        """Retrieves structured evidence audit events recorded by the target."""
        pass


class HTTPTargetAdapter(BaseTargetAdapter):
    """Generic HTTP Target Adapter supporting standard AuthTime REST protocol."""

    async def _get_client(self) -> Tuple[httpx.AsyncClient, bool]:
        if self._shared_client is not None:
            return self._shared_client, False
        return httpx.AsyncClient(timeout=5.0), True

    async def verify_identity(self) -> Dict[str, Any]:
        client, should_close = await self._get_client()
        try:
            resp = await client.get(f"{self.target_url}/target/identity")
            if resp.status_code != 200:
                raise RuntimeError(f"Target identity endpoint returned status {resp.status_code}")
            return resp.json()
        finally:
            if should_close:
                await client.aclose()

    async def reset_state(self, experiment_id: Optional[str] = None) -> Dict[str, Any]:
        client, should_close = await self._get_client()
        headers = {"X-AuthTime-Request-ID": f"reset-{experiment_id or 'global'}"}
        if experiment_id:
            headers["X-AuthTime-Experiment-ID"] = experiment_id

        try:
            resp = await client.post(f"{self.target_url}/faults/reset", headers=headers)
            resp.raise_for_status()
            return resp.json()
        finally:
            if should_close:
                await client.aclose()

    async def login_user(self, user_id: str) -> str:
        client, should_close = await self._get_client()
        try:
            resp = await client.post(f"{self.target_url}/auth/login", json={"user_id": user_id})
            resp.raise_for_status()
            return resp.json()["access_token"]
        finally:
            if should_close:
                await client.aclose()

    async def inject_fault(
        self,
        fault_type: str,
        user_id: str,
        new_role: Optional[str] = "User",
        cache_ttl_seconds: float = 60.0,
        time_scale_factor: float = 1.0,
        experiment_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        client, should_close = await self._get_client()
        payload = {
            "fault_type": fault_type,
            "user_id": user_id,
            "new_role": new_role,
            "cache_ttl_seconds": cache_ttl_seconds,
            "time_scale_factor": time_scale_factor,
            "experiment_id": experiment_id,
        }
        headers = {"X-AuthTime-Request-ID": f"fault-{experiment_id or 'global'}"}
        if experiment_id:
            headers["X-AuthTime-Experiment-ID"] = experiment_id

        try:
            resp = await client.post(f"{self.target_url}/faults/inject", json=payload, headers=headers)
            resp.raise_for_status()
            return resp.json()
        finally:
            if should_close:
                await client.aclose()

    async def probe_endpoint(
        self,
        resource_path: str,
        token: Optional[str],
        request_id: str,
        experiment_id: Optional[str] = None,
    ) -> Tuple[int, str, float]:
        client, should_close = await self._get_client()
        headers = {"X-AuthTime-Request-ID": request_id}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if experiment_id:
            headers["X-AuthTime-Experiment-ID"] = experiment_id

        url = f"{self.target_url}{resource_path}"
        try:
            resp = await client.get(url, headers=headers)
            lat_ms = resp.elapsed.total_seconds() * 1000.0 if hasattr(resp, "elapsed") else 0.0
            return resp.status_code, resp.text, lat_ms

        finally:
            if should_close:
                await client.aclose()

    async def fetch_evidence_events(self, experiment_id: str) -> List[Dict[str, Any]]:
        client, should_close = await self._get_client()
        try:
            resp = await client.get(f"{self.target_url}/events", params={"experiment_id": experiment_id})
            if resp.status_code != 200:
                return []
            return resp.json().get("events", [])
        finally:
            if should_close:
                await client.aclose()
