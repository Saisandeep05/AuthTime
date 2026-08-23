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


class DistributedLabAdapter(BaseTargetAdapter):
    """
    Distributed Authorization Validation Laboratory Adapter.
    Manages identity, fault injection, multi-replica probing, and per-replica exposure calculations
    across multiple protected API instances (API-1, API-2, API-3).
    """

    def __init__(
        self,
        replica_urls: Optional[List[str]] = None,
        primary_url: str = "http://127.0.0.1:8010",
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        super().__init__(target_url=primary_url, http_client=http_client)
        self.replica_urls = [u.rstrip("/") for u in (replica_urls or [primary_url, "http://127.0.0.1:8011", "http://127.0.0.1:8012"])]

    async def _get_client(self) -> Tuple[httpx.AsyncClient, bool]:
        if self._shared_client is not None:
            return self._shared_client, False
        return httpx.AsyncClient(timeout=5.0), True

    async def verify_identity(self) -> Dict[str, Any]:
        client, should_close = await self._get_client()
        try:
            replica_identities = []
            for url in self.replica_urls:
                try:
                    resp = await client.get(f"{url}/identity")
                    if resp.status_code == 200:
                        replica_identities.append(resp.json())
                except Exception:
                    pass

            return {
                "product": "AuthTime",
                "target": "authtime-distributed-lab",
                "replica_count": len(self.replica_urls),
                "active_replicas": len(replica_identities),
                "replicas": replica_identities,
                "capabilities": ["multi_replica", "redis_cache", "postgres_db", "jwt_auth"],
            }
        finally:
            if should_close:
                await client.aclose()

    async def reset_state(self, experiment_id: Optional[str] = None) -> Dict[str, Any]:
        client, should_close = await self._get_client()
        try:
            resp = await client.post(f"{self.target_url}/reset")
            if resp.status_code in (200, 201):
                return resp.json()
            return {"status": "RESET_SUBMITTED"}
        except Exception:
            return {"status": "RESET_SKIPPED"}
        finally:
            if should_close:
                await client.aclose()

    async def login_user(self, user_id: str) -> str:
        client, should_close = await self._get_client()
        try:
            resp = await client.post(f"{self.target_url}/login", json={"user_id": user_id})
            resp.raise_for_status()
            data = resp.json()
            return data["access_token"]
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
        try:
            mode_map = {
                "STALE_CACHE": "ttl",
                "DELAYED_INVALIDATION": "delayed",
                "PARTIAL_PROPAGATION": "partial_replica",
                "DROPPED_EVENT": "dropped_event",
                "REDIS_UNAVAILABLE": "unavailable",
                "NO_FAULT": "normal",
            }
            lab_mode = mode_map.get(fault_type.upper(), "normal")

            await client.post(
                f"{self.target_url}/faults/configure-cache-mode",
                json={
                    "mode": lab_mode,
                    "delay_sec": cache_ttl_seconds if lab_mode == "delayed" else 2.0,
                    "target_replica": "api-2" if lab_mode == "partial_replica" else ("api-3" if lab_mode == "dropped_event" else None),
                    "ttl_sec": cache_ttl_seconds,
                },
            )

            resp = await client.post(
                f"{self.target_url}/faults/revoke",
                json={"user_id": user_id, "new_role": new_role},
            )
            resp.raise_for_status()
            data = resp.json()

            return {
                "fault_type": fault_type,
                "lab_mode": lab_mode,
                "user_id": user_id,
                "new_role": new_role,
                "event": data.get("event", {}),
                "authoritative_timestamp": data.get("event", {}).get("authoritative_timestamp"),
            }
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

        try:
            resp = await client.get(f"{self.target_url}{resource_path}", headers=headers)
            lat_ms = resp.elapsed.total_seconds() * 1000.0 if hasattr(resp, "elapsed") else 0.0
            return resp.status_code, resp.text, lat_ms
        finally:
            if should_close:
                await client.aclose()

    async def probe_all_replicas(
        self,
        resource_path: str,
        token: Optional[str],
        request_id: str,
    ) -> Dict[str, Tuple[int, str, float]]:
        client, should_close = await self._get_client()
        results = {}
        headers = {"X-AuthTime-Request-ID": request_id}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            for i, url in enumerate(self.replica_urls):
                replica_name = f"api-{i+1}"
                try:
                    resp = await client.get(f"{url}{resource_path}", headers=headers)
                    lat_ms = resp.elapsed.total_seconds() * 1000.0 if hasattr(resp, "elapsed") else 0.0
                    results[replica_name] = (resp.status_code, resp.text, lat_ms)
                except Exception as e:
                    results[replica_name] = (503, str(e), 0.0)
            return results
        finally:
            if should_close:
                await client.aclose()

    async def fetch_evidence_events(self, experiment_id: str) -> List[Dict[str, Any]]:
        client, should_close = await self._get_client()
        try:
            resp = await client.get(f"{self.target_url}/events")
            if resp.status_code == 200:
                return resp.json().get("events", [])
            return []
        except Exception:
            return []
        finally:
            if should_close:
                await client.aclose()

    def calculate_per_replica_exposure(
        self,
        replica_probe_logs: Dict[str, List[Dict[str, Any]]],
        t0_authoritative: float,
    ) -> Dict[str, Any]:
        per_replica_metrics = {}
        exposure_durations = []

        for replica_id, logs in replica_probe_logs.items():
            t_first_allow = None
            t_last_allow = None
            t_first_deny = None

            for log in logs:
                t_mono = log.get("timestamp_monotonic", 0.0)
                status_code = log.get("status_code", 0)

                if status_code == 200:
                    if t_first_allow is None:
                        t_first_allow = t_mono
                    t_last_allow = t_mono
                elif status_code == 403:
                    if t_first_deny is None:
                        t_first_deny = t_mono

            if t_last_allow and t_last_allow > t0_authoritative:
                dt_lower = max(0.0, t_last_allow - t0_authoritative)
                dt_upper = max(0.0, (t_first_deny - t0_authoritative) if t_first_deny else dt_lower)
            else:
                dt_lower = 0.0
                dt_upper = 0.0

            exposure_durations.append(dt_upper)
            per_replica_metrics[replica_id] = {
                "t0_authoritative": t0_authoritative,
                "t_last_allow": t_last_allow,
                "t_first_deny": t_first_deny,
                "dt_exposure_lower_bound_sec": dt_lower,
                "dt_exposure_upper_bound_sec": dt_upper,
            }

        min_exp = min(exposure_durations) if exposure_durations else 0.0
        max_exp = max(exposure_durations) if exposure_durations else 0.0
        mean_exp = (sum(exposure_durations) / len(exposure_durations)) if exposure_durations else 0.0

        return {
            "per_replica": per_replica_metrics,
            "aggregate": {
                "min_exposure_sec": min_exp,
                "max_exposure_sec": max_exp,
                "mean_exposure_sec": mean_exp,
                "replica_count": len(per_replica_metrics),
            },
        }

