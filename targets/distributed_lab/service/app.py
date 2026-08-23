"""
AuthTime Distributed Lab - Multi-Replica Protected API Application Factory.
Provides FastAPI service replicas representing API-1, API-2, and API-3 nodes.
"""

import os
import time
import asyncio
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel

from targets.distributed_lab.db.database import LabDatabase
from targets.distributed_lab.cache.redis_cache import LabRedisCache
from targets.distributed_lab.auth.jwt_handler import LabJWTHandler


class LoginRequest(BaseModel):
    user_id: str = "admin1"


class RevokeRequest(BaseModel):
    user_id: str = "admin1"
    new_role: str = "User"


class FaultConfigRequest(BaseModel):
    mode: str = "normal"  # 'normal', 'ttl', 'delayed', 'partial_replica', 'dropped_event', 'unavailable'
    delay_sec: float = 0.0
    target_replica: Optional[str] = None
    ttl_sec: float = 60.0


def create_lab_replica_app(
    replica_id: str = "api-1",
    db: Optional[LabDatabase] = None,
    cache: Optional[LabRedisCache] = None,
    jwt_handler: Optional[LabJWTHandler] = None,
    all_replica_ids: Optional[List[str]] = None,
) -> FastAPI:
    """Factory creating an independent, identifiable API replica service instance."""

    app = FastAPI(
        title=f"AuthTime Distributed Lab API Replica [{replica_id}]",
        version="1.0.0",
    )

    db_instance = db or LabDatabase()
    cache_instance = cache or LabRedisCache()
    jwt_instance = jwt_handler or LabJWTHandler()
    replica_list = all_replica_ids or ["api-1", "api-2", "api-3"]

    @app.on_event("startup")
    async def startup_event():
        await db_instance.initialize()
        await cache_instance.initialize()

    @app.get("/identity")
    async def identity():
        return {
            "product": "AuthTime",
            "target": "authtime-distributed-lab",
            "replica_id": replica_id,
            "status": "HEALTHY",
            "capabilities": ["multi_replica", "redis_cache", "postgres_db", "jwt_auth"],
        }

    @app.post("/login")
    async def login(req: LoginRequest):
        role = await db_instance.get_user_role(req.user_id)
        auth_ver = await db_instance.get_auth_version(req.user_id)
        token = jwt_instance.create_access_token(
            user_id=req.user_id,
            role=role,
            auth_version=auth_ver,
            ttl_sec=3600.0,
        )
        return {
            "access_token": token,
            "token_type": "bearer",
            "user_id": req.user_id,
            "role": role,
            "auth_version": auth_ver,
            "replica_id": replica_id,
        }

    mitigation_state = {"enabled": False}

    async def _authorize_request(authorization: Optional[str], required_roles: List[str], resource_path: str) -> Dict[str, Any]:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or malformed Authorization header",
            )

        raw_token = authorization.split(" ")[1]
        try:
            payload = jwt_instance.verify_access_token(raw_token)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(e),
            )

        user_id = payload.get("sub", "admin1")
        token_auth_ver = payload.get("auth_ver", 1)

        # In Mitigation Mode: Version-Aware Cache Validation
        if mitigation_state["enabled"]:
            auth_db_ver = await db_instance.get_auth_version(user_id)
            cached = await cache_instance.get_cached_authorization(user_id, replica_id)
            cached_ver = cached.get("auth_version", 1) if cached else 1

            if token_auth_ver < auth_db_ver or cached_ver < auth_db_ver:
                # Version mismatch detected -> Evict stale cache entry immediately
                await cache_instance.invalidate_user(user_id, "Evicted", auth_db_ver, [replica_id])
                role = await db_instance.get_user_role(user_id)
                await cache_instance.set_cached_authorization(user_id, role, auth_db_ver, replica_id)
                is_stale = False
            elif cached:
                role = cached["role"]
                is_stale = False
            else:
                role = await db_instance.get_user_role(user_id)
                await cache_instance.set_cached_authorization(user_id, role, auth_db_ver, replica_id)
                is_stale = False
        else:
            # Vulnerable Mode: Normal cache lookup (subject to stale cache / delayed propagation / dropped events)
            cached = await cache_instance.get_cached_authorization(user_id, replica_id)
            if cached:
                role = cached["role"]
                is_stale = cached.get("is_stale", False)
            else:
                role = await db_instance.get_user_role(user_id)
                auth_ver = await db_instance.get_auth_version(user_id)
                await cache_instance.set_cached_authorization(user_id, role, auth_ver, replica_id)
                is_stale = False

        if role in required_roles:
            return {
                "status": "ALLOW",
                "user_id": user_id,
                "role": role,
                "is_stale": is_stale,
                "replica_id": replica_id,
                "resource_path": resource_path,
                "timestamp_monotonic": time.monotonic(),
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Requires {required_roles} role (current role: {role})",
            )

    @app.get("/admin/users")
    async def get_admin_users(authorization: Optional[str] = Header(None)):
        return await _authorize_request(authorization, ["Admin"], "/admin/users")

    @app.get("/finance/payroll")
    async def get_finance_payroll(authorization: Optional[str] = Header(None)):
        return await _authorize_request(authorization, ["Finance Admin", "Admin"], "/finance/payroll")

    @app.get("/finance/payments")
    async def get_finance_payments(authorization: Optional[str] = Header(None)):
        return await _authorize_request(authorization, ["Finance Admin", "Admin"], "/finance/payments")

    @app.get("/finance/reports")
    async def get_finance_reports(authorization: Optional[str] = Header(None)):
        return await _authorize_request(authorization, ["Finance Admin", "Admin"], "/finance/reports")

    peer_ports = [8010, 8011, 8012]

    async def _broadcast_to_peers(endpoint: str, json_data: dict):
        import httpx
        async with httpx.AsyncClient(timeout=0.5) as client:
            for p in peer_ports:
                try:
                    await client.post(f"http://127.0.0.1:{p}{endpoint}?broadcast=false", json=json_data)
                except Exception:
                    pass

    @app.post("/faults/revoke")
    async def revoke_user(req: RevokeRequest, broadcast: bool = True):
        event = await db_instance.revoke_user_role(req.user_id, req.new_role)
        auth_ver = event["auth_version"]
        await cache_instance.invalidate_user(req.user_id, req.new_role, auth_ver, replica_list)

        if broadcast:
            await _broadcast_to_peers("/faults/revoke", req.model_dump())

        return {
            "status": "REVOKED",
            "event": event,
            "replica_id": replica_id,
        }

    @app.post("/faults/configure-cache-mode")
    async def configure_cache_mode(req: FaultConfigRequest, broadcast: bool = True):
        cache_instance.configure_fault_mode(
            mode=req.mode,
            delay_sec=req.delay_sec,
            target_replica=req.target_replica,
            ttl_sec=req.ttl_sec,
        )

        if broadcast:
            await _broadcast_to_peers("/faults/configure-cache-mode", req.model_dump())

        return {
            "status": "CONFIGURED",
            "mode": req.mode,
            "delay_sec": req.delay_sec,
            "target_replica": req.target_replica,
            "ttl_sec": req.ttl_sec,
        }

    @app.post("/faults/configure-mitigation")
    async def configure_mitigation(req: Dict[str, Any], broadcast: bool = True):
        mitigation_state["enabled"] = req.get("enabled", True)

        if broadcast:
            await _broadcast_to_peers("/faults/configure-mitigation", req)

        return {
            "status": "MITIGATION_CONFIGURED",
            "enabled": mitigation_state["enabled"],
            "replica_id": replica_id,
        }

    @app.post("/reset")
    async def reset(broadcast: bool = True):
        await db_instance.reset_database()
        await cache_instance.clear_cache()
        mitigation_state["enabled"] = False

        if broadcast:
            import httpx
            async with httpx.AsyncClient(timeout=0.5) as client:
                for p in peer_ports:
                    try:
                        await client.post(f"http://127.0.0.1:{p}/reset?broadcast=false")
                    except Exception:
                        pass

        return {"status": "RESET_COMPLETE", "replica_id": replica_id}

    @app.get("/events")
    async def get_events():
        events = await db_instance.get_revocation_events()
        return {"events": events, "replica_id": replica_id}

    return app

