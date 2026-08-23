"""
FastAPI Routes for Reference Auth Target and Fault Injection Interface.
"""

from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Header, Request, status
from pydantic import BaseModel

from app.config import settings
from app.auth.jwt import create_jwt_token, verify_jwt_token
from app.rbac.roles import has_permission, get_role_permissions
from app.cache.ttl_cache import auth_cache
from app.models.db import db

router = APIRouter()

# Global event audit log buffer for EventCollector
audit_events: list[dict] = []


def record_audit_event(
    request_id: str,
    event_type: str,
    user_id: Optional[str],
    role: Optional[str],
    endpoint: str,
    decision: str,
    status_code: int,
    details: Dict[str, Any],
):
    import time
    from datetime import datetime, timezone

    audit_events.append({
        "event_id": f"evt-{len(audit_events) + 1}",
        "request_id": request_id,
        "monotonic_timestamp": time.monotonic(),
        "utc_timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "user_id": user_id,
        "role": role,
        "endpoint": endpoint,
        "decision": decision,
        "status_code": status_code,
        "details": details,
    })


class LoginRequest(BaseModel):
    user_id: str
    ttl_seconds: Optional[int] = None


class FaultInjectRequest(BaseModel):
    fault_type: str
    user_id: Optional[str] = "admin1"
    new_role: Optional[str] = "User"
    cache_ttl_seconds: Optional[float] = None
    time_scale_factor: Optional[float] = 1.0


def enforce_local_only_fault_api(request: Request):
    """Safety guard: ensure fault injection endpoints are strictly local."""
    client_host = request.client.host if request.client else "unknown"
    if client_host not in ("127.0.0.1", "localhost", "::1", "testclient"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Fault injection endpoints are restricted to local loopback (127.0.0.1).",
        )


async def get_current_user_authorization(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_authtime_request_id: Optional[str] = Header(None, alias="X-AuthTime-Request-ID"),
) -> Dict[str, Any]:
    req_id = x_authtime_request_id or "untracked"

    if not authorization or not authorization.startswith("Bearer "):
        record_audit_event(req_id, "AUTH_CHECK", None, None, request.url.path, "DENY", 401, {"reason": "Missing token"})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid Bearer token")

    token = authorization.split(" ")[1]
    claims = verify_jwt_token(token)
    if not claims:
        record_audit_event(req_id, "AUTH_CHECK", None, None, request.url.path, "DENY", 401, {"reason": "Expired/Invalid JWT"})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    user_id = claims.get("sub")
    jwt_role = claims.get("role")

    # Check Authorization Cache first
    cache_key = f"auth:{user_id}"
    cached_state, cache_hit = auth_cache.get(cache_key)

    if cache_hit and cached_state is not None:
        effective_role = cached_state["role"]
        record_audit_event(req_id, "CACHE_HIT", user_id, effective_role, request.url.path, "ALLOW", 200, {"cache_hit": True, "source": "cache"})
        return {"user_id": user_id, "role": effective_role, "cache_hit": True, "claims": claims}

    # Cache miss: query DB state
    user_rec = db.get_user(user_id)
    if not user_rec or not user_rec.is_active:
        record_audit_event(req_id, "AUTH_CHECK", user_id, None, request.url.path, "DENY", 403, {"reason": "Inactive user"})
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account disabled")

    effective_role = user_rec.role
    auth_state = {"role": effective_role, "permissions": list(get_role_permissions(effective_role))}

    # Cache the authorization decision
    auth_cache.set(cache_key, auth_state)

    record_audit_event(req_id, "CACHE_MISS", user_id, effective_role, request.url.path, "ALLOW", 200, {"cache_hit": False, "source": "db"})
    return {"user_id": user_id, "role": effective_role, "cache_hit": False, "claims": claims}


@router.post("/auth/login")
async def login(req: LoginRequest):
    user = db.get_user(req.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    token = create_jwt_token(user.user_id, user.role, req.ttl_seconds)
    return {"access_token": token, "token_type": "bearer", "user_id": user.user_id, "role": user.role}


@router.get("/invoices/{id}")
async def get_invoice(id: str, request: Request, auth: Dict[str, Any] = Depends(get_current_user_authorization)):
    req_id = request.headers.get("X-AuthTime-Request-ID", "untracked")
    role = auth["role"]
    if not has_permission(role, "READ_INVOICE"):
        record_audit_event(req_id, "RESOURCE_ACCESS", auth["user_id"], role, f"/invoices/{id}", "DENY", 403, {"permission": "READ_INVOICE"})
        raise HTTPException(status_code=403, detail="Forbidden: Insufficient permissions")

    record_audit_event(req_id, "RESOURCE_ACCESS", auth["user_id"], role, f"/invoices/{id}", "ALLOW", 200, {"permission": "READ_INVOICE"})
    return {"invoice_id": id, "amount": 1500.00, "status": "PAID", "accessed_by": auth["user_id"], "role": role}


@router.get("/admin/users")
async def get_admin_users(request: Request, auth: Dict[str, Any] = Depends(get_current_user_authorization)):
    req_id = request.headers.get("X-AuthTime-Request-ID", "untracked")
    role = auth["role"]
    if not has_permission(role, "MANAGE_USERS"):
        record_audit_event(req_id, "RESOURCE_ACCESS", auth["user_id"], role, "/admin/users", "DENY", 403, {"permission": "MANAGE_USERS"})
        raise HTTPException(status_code=403, detail="Forbidden: Admin permission required")

    record_audit_event(req_id, "RESOURCE_ACCESS", auth["user_id"], role, "/admin/users", "ALLOW", 200, {"users": list(db.users.keys()), "accessed_by": auth["user_id"], "role": role})
    return {"users": [u.model_dump() for u in db.users.values()], "accessed_by": auth["user_id"], "role": role}


@router.post("/faults/inject", dependencies=[Depends(enforce_local_only_fault_api)])
async def inject_fault(req: FaultInjectRequest, request: Request):
    req_id = request.headers.get("X-AuthTime-Request-ID", "untracked")

    if req.cache_ttl_seconds is not None:
        auth_cache.default_ttl = req.cache_ttl_seconds * (req.time_scale_factor or 1.0)

    if req.fault_type == "role_revocation":
        # Revoke user role in DB, but do NOT clear the auth_cache automatically
        db.update_role(req.user_id, req.new_role or "User")
        record_audit_event(req_id, "FAULT_INJECTED", req.user_id, req.new_role, "/faults/inject", "EXECUTED", 200, {"fault_type": "role_revocation", "new_role": req.new_role})
        return {"status": "SUCCESS", "fault": "role_revocation", "user_id": req.user_id, "new_role": req.new_role}

    elif req.fault_type == "stale_cache":
        # Force stale cache entry retention
        cache_key = f"auth:{req.user_id}"
        stale_data = {"role": "Admin", "permissions": ["READ_INVOICE", "MANAGE_USERS"]}
        ttl = (req.cache_ttl_seconds or 60.0) * (req.time_scale_factor or 1.0)
        auth_cache.set_stale(cache_key, stale_data, extend_seconds=ttl)
        db.update_role(req.user_id, "User")
        record_audit_event(req_id, "FAULT_INJECTED", req.user_id, "User", "/faults/inject", "EXECUTED", 200, {"fault_type": "stale_cache", "stale_ttl": ttl})
        return {"status": "SUCCESS", "fault": "stale_cache", "user_id": req.user_id, "stale_ttl": ttl}

    elif req.fault_type == "token_expiry":
        db.update_role(req.user_id, "User")
        auth_cache.invalidate(f"auth:{req.user_id}")
        record_audit_event(req_id, "FAULT_INJECTED", req.user_id, "User", "/faults/inject", "EXECUTED", 200, {"fault_type": "token_expiry"})
        return {"status": "SUCCESS", "fault": "token_expiry", "user_id": req.user_id}

    elif req.fault_type == "agent_session_revocation":
        db.update_role(req.user_id, "User")
        record_audit_event(req_id, "FAULT_INJECTED", req.user_id, "User", "/faults/inject", "EXECUTED", 200, {"fault_type": "agent_session_revocation"})
        return {"status": "SUCCESS", "fault": "agent_session_revocation", "user_id": req.user_id}

    raise HTTPException(status_code=400, detail=f"Unknown fault type: {req.fault_type}")


@router.post("/faults/reset", dependencies=[Depends(enforce_local_only_fault_api)])
async def reset_faults(request: Request):
    db.reset_to_defaults()
    auth_cache.clear()
    auth_cache.default_ttl = settings.DEFAULT_CACHE_TTL_SECONDS
    audit_events.clear()
    return {"status": "SUCCESS", "message": "State and cache reset to baseline defaults"}


@router.get("/events")
async def get_audit_events():
    return {"events": audit_events}
