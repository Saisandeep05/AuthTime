"""
Reference Application API Routes & Fault Injection Controller.
"""

from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Header, HTTPException, Request, Depends, status
from pydantic import BaseModel
import time
from datetime import datetime, timezone

from app.auth.jwt import create_access_token, decode_access_token
from app.rbac.roles import USER_ROLES_DB, has_permission, RoleEnum
from app.cache.ttl_cache import auth_cache

router = APIRouter()

# Structured Audit Event Store
EVENT_STORE: List[Dict[str, Any]] = []


class LoginRequest(BaseModel):
    user_id: str
    ttl_seconds: Optional[int] = None


class FaultInjectRequest(BaseModel):
    fault_type: str  # "stale_cache", "role_revocation", "token_expiry", "agent_session_revocation"
    user_id: str
    new_role: Optional[str] = "User"
    cache_ttl_seconds: Optional[float] = 60.0
    time_scale_factor: Optional[float] = 1.0


def enforce_local_client(request: Request):
    client_host = request.client.host if request.client else "127.0.0.1"
    if client_host not in ("127.0.0.1", "localhost", "::1", "testclient"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="SAFETY ERROR: Fault injection endpoints are strictly restricted to local loopback 127.0.0.1.",
        )


def record_audit_event(request_id: str, event_type: str, details: Dict[str, Any]):
    EVENT_STORE.append({
        "event_id": f"evt-{len(EVENT_STORE)+1}",
        "request_id": request_id,
        "monotonic_timestamp": time.monotonic(),
        "utc_timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "details": details,
    })


@router.post("/auth/login")
def login(req: LoginRequest):
    role = USER_ROLES_DB.get(req.user_id, RoleEnum.USER.value)
    token = create_access_token(req.user_id, role, req.ttl_seconds)
    return {"access_token": token, "token_type": "bearer", "user_id": req.user_id, "role": role}


@router.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: str, authorization: str = Header(...), x_authtime_request_id: str = Header(default="anon")):
    token = authorization.replace("Bearer ", "").strip()
    payload = decode_access_token(token)
    user_id = payload["sub"]

    # Cache Lookup
    cached_role = auth_cache.get(f"auth:{user_id}")
    if cached_role:
        role = cached_role
        cache_hit = True
    else:
        role = USER_ROLES_DB.get(user_id, payload.get("role", RoleEnum.USER.value))
        auth_cache.set(f"auth:{user_id}", role)
        cache_hit = False

    record_audit_event(x_authtime_request_id, "AUTH_CHECK", {"user_id": user_id, "role": role, "cache_hit": cache_hit})

    if not has_permission(role, "invoices:read"):
        raise HTTPException(status_code=403, detail="Permission Denied")

    return {"invoice_id": invoice_id, "status": "PAID", "amount": 1500.00}


@router.get("/admin/users")
def get_admin_users(authorization: str = Header(...), x_authtime_request_id: str = Header(default="anon")):
    token = authorization.replace("Bearer ", "").strip()
    try:
        payload = decode_access_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid Token")

    user_id = payload["sub"]

    cached_role = auth_cache.get(f"auth:{user_id}")
    if cached_role:
        role = cached_role
        cache_hit = True
    else:
        role = USER_ROLES_DB.get(user_id, payload.get("role", RoleEnum.USER.value))
        auth_cache.set(f"auth:{user_id}", role)
        cache_hit = False

    record_audit_event(x_authtime_request_id, "AUTH_CHECK", {"user_id": user_id, "role": role, "cache_hit": cache_hit})

    if not has_permission(role, "admin:read"):
        raise HTTPException(status_code=403, detail="Permission Denied")

    return {"users": ["admin1", "user1", "guest1"], "count": 3}


@router.post("/faults/inject", dependencies=[Depends(enforce_local_client)])
def inject_fault(req: FaultInjectRequest, x_authtime_request_id: str = Header(default="fault-inject")):
    user_id = req.user_id

    if req.fault_type == "stale_cache":
        # Simulate stale cache: Update DB role to revoked, but inject/retain old role in cache!
        old_role = USER_ROLES_DB.get(user_id, RoleEnum.ADMIN.value)
        USER_ROLES_DB[user_id] = req.new_role or RoleEnum.USER.value
        effective_cache_ttl = (req.cache_ttl_seconds or 60.0) * (req.time_scale_factor or 1.0)
        auth_cache.set(f"auth:{user_id}", old_role, ttl_seconds=effective_cache_ttl)

    elif req.fault_type == "role_revocation":
        # Immediate DB revocation and cache invalidation
        USER_ROLES_DB[user_id] = req.new_role or RoleEnum.USER.value
        auth_cache.delete(f"auth:{user_id}")

    elif req.fault_type == "agent_session_revocation":
        # Delegated session fault: human delegator revoked, but token remains active until expiry
        USER_ROLES_DB[user_id] = RoleEnum.USER.value
        auth_cache.delete(f"auth:{user_id}")

    record_audit_event(x_authtime_request_id, "FAULT_INJECTED", req.model_dump())

    return {"status": "SUCCESS", "fault_type": req.fault_type, "target_user": user_id}


@router.post("/faults/reset", dependencies=[Depends(enforce_local_client)])
def reset_faults(x_authtime_request_id: str = Header(default="fault-reset")):
    auth_cache.clear()
    USER_ROLES_DB.clear()
    USER_ROLES_DB.update({
        "admin1": RoleEnum.ADMIN.value,
        "user1": RoleEnum.USER.value,
        "guest1": RoleEnum.GUEST.value,
        "svc1": RoleEnum.SERVICE_ACCOUNT.value,
    })
    EVENT_STORE.clear()
    record_audit_event(x_authtime_request_id, "FAULT_RESET", {"status": "RESET_COMPLETE"})
    return {"status": "RESET_COMPLETE"}


@router.get("/events")
def get_events(experiment_id: Optional[str] = None):
    return {"events": EVENT_STORE}
