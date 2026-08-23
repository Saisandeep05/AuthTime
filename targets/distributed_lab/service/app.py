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

    @app.get("/admin/users")
    async def get_admin_users(authorization: Optional[str] = Header(None)):
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

        # Step 1: Check Redis cache for this user and replica
        cached = await cache_instance.get_cached_authorization(user_id, replica_id)
        if cached:
            role = cached["role"]
            is_stale = cached.get("is_stale", False)
        else:
            # Step 2: Cache miss -> Query authoritative PostgreSQL database
            role = await db_instance.get_user_role(user_id)
            auth_ver = await db_instance.get_auth_version(user_id)
            await cache_instance.set_cached_authorization(user_id, role, auth_ver)
            is_stale = False

        if role == "Admin":
            return {
                "status": "ALLOW",
                "user_id": user_id,
                "role": role,
                "is_stale": is_stale,
                "replica_id": replica_id,
                "timestamp_monotonic": time.monotonic(),
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Requires Admin role (current role: {role})",
            )

    @app.post("/faults/revoke")
    async def revoke_user(req: RevokeRequest):
        event = await db_instance.revoke_user_role(req.user_id, req.new_role)
        auth_ver = event["auth_version"]
        await cache_instance.invalidate_user(req.user_id, req.new_role, auth_ver, replica_list)
        return {
            "status": "REVOKED",
            "event": event,
            "replica_id": replica_id,
        }

    @app.post("/faults/configure-cache-mode")
    async def configure_cache_mode(req: FaultConfigRequest):
        cache_instance.configure_fault_mode(
            mode=req.mode,
            delay_sec=req.delay_sec,
            target_replica=req.target_replica,
            ttl_sec=req.ttl_sec,
        )
        return {
            "status": "CONFIGURED",
            "mode": req.mode,
            "delay_sec": req.delay_sec,
            "target_replica": req.target_replica,
            "ttl_sec": req.ttl_sec,
        }

    @app.post("/reset")
    async def reset():
        await db_instance.reset_database()
        await cache_instance.clear_cache()
        return {"status": "RESET_COMPLETE", "replica_id": replica_id}

    @app.get("/events")
    async def get_events():
        events = await db_instance.get_revocation_events()
        return {"events": events, "replica_id": replica_id}

    return app
