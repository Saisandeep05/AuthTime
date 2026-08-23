"""
Reference Application API Routes & Fault Injection Controller.
"""

import os
import uuid
import time
from typing import Dict, Any, Optional, List, Literal
from datetime import datetime, timezone

from fastapi import APIRouter, Header, HTTPException, Request, Depends, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.auth.jwt import create_access_token, decode_access_token
from app.rbac.roles import USER_ROLES_DB, has_permission, RoleEnum
from app.cache.ttl_cache import auth_cache

router = APIRouter()

# Structured Audit Event Store (Immutable Audit Trail)
EVENT_STORE: List[Dict[str, Any]] = []


@router.get("/", response_class=HTMLResponse)
def get_dashboard():
    static_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "index.html")
    if os.path.exists(static_path):
        with open(static_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>AuthTime Control Center Target Server Active</h1>"


class LoginRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=128)
    ttl_seconds: Optional[int] = Field(None, gt=0)


class FaultInjectRequest(BaseModel):
    fault_type: Literal["stale_cache", "role_revocation", "token_expiry", "agent_session_revocation", "cross_user_isolation"]
    user_id: str = Field(..., min_length=1, max_length=128)
    secondary_user_id: Optional[str] = Field(None, min_length=1, max_length=128)
    new_role: Optional[str] = "User"
    cache_ttl_seconds: float = Field(60.0, gt=0.0)
    time_scale_factor: float = Field(1.0, gt=0.0, le=10.0)
    experiment_id: Optional[str] = None
    trial_id: Optional[str] = None


def enforce_local_client(request: Request):
    client_host = request.client.host if request.client else "127.0.0.1"
    if client_host not in ("127.0.0.1", "localhost", "::1", "testclient"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="SAFETY ERROR: Control plane and evidence endpoints are restricted strictly to local loopback (127.0.0.1).",
        )


def record_audit_event(
    request_id: str,
    event_type: str,
    details: Dict[str, Any],
    experiment_id: Optional[str] = None,
    trial_id: Optional[str] = None,
):
    """Records an audit event into the immutable process event store with full UUID identity."""
    EVENT_STORE.append({
        "event_id": f"evt-{uuid.uuid4()}",
        "request_id": request_id,
        "experiment_id": experiment_id or details.get("experiment_id") or "global",
        "trial_id": trial_id or details.get("trial_id"),
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
def get_invoice(
    invoice_id: str,
    authorization: str = Header(...),
    x_authtime_request_id: str = Header(default="anon"),
    x_authtime_experiment_id: Optional[str] = Header(default=None),
    x_authtime_trial_id: Optional[str] = Header(default=None),
):
    token = authorization.replace("Bearer ", "").strip()
    payload = decode_access_token(token)
    user_id = payload["sub"]

    cached_role = auth_cache.get(f"auth:{user_id}")
    if cached_role:
        role = cached_role
        cache_hit = True
    else:
        role = USER_ROLES_DB.get(user_id, payload.get("role", RoleEnum.USER.value))
        auth_cache.set(f"auth:{user_id}", role)
        cache_hit = False

    record_audit_event(
        x_authtime_request_id,
        "AUTH_CHECK",
        {"user_id": user_id, "role": role, "cache_hit": cache_hit},
        experiment_id=x_authtime_experiment_id,
        trial_id=x_authtime_trial_id,
    )

    if not has_permission(role, "invoices:read"):
        raise HTTPException(status_code=403, detail="Permission Denied")

    return {"invoice_id": invoice_id, "status": "PAID", "amount": 1500.00}


@router.get("/admin/users")
def get_admin_users(
    authorization: str = Header(...),
    x_authtime_request_id: str = Header(default="anon"),
    x_authtime_experiment_id: Optional[str] = Header(default=None),
    x_authtime_trial_id: Optional[str] = Header(default=None),
):
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

    record_audit_event(
        x_authtime_request_id,
        "AUTH_CHECK",
        {"user_id": user_id, "role": role, "cache_hit": cache_hit},
        experiment_id=x_authtime_experiment_id,
        trial_id=x_authtime_trial_id,
    )

    if not has_permission(role, "admin:read"):
        raise HTTPException(status_code=403, detail="Permission Denied")

    return {"users": ["admin1", "user1", "guest1"], "count": 3}


@router.post("/faults/inject", dependencies=[Depends(enforce_local_client)])
def inject_fault(
    req: FaultInjectRequest,
    x_authtime_request_id: str = Header(default="fault-inject"),
    x_authtime_experiment_id: Optional[str] = Header(default=None),
    x_authtime_trial_id: Optional[str] = Header(default=None),
):
    user_id = req.user_id
    t_fault_applied = time.monotonic()
    exp_id = req.experiment_id or x_authtime_experiment_id
    tr_id = req.trial_id or x_authtime_trial_id

    if req.fault_type == "stale_cache":
        old_role = USER_ROLES_DB.get(user_id, RoleEnum.ADMIN.value)
        USER_ROLES_DB[user_id] = req.new_role or RoleEnum.USER.value
        effective_cache_ttl = req.cache_ttl_seconds * req.time_scale_factor
        auth_cache.set(f"auth:{user_id}", old_role, ttl_seconds=effective_cache_ttl)

    elif req.fault_type == "role_revocation":
        USER_ROLES_DB[user_id] = req.new_role or RoleEnum.USER.value
        auth_cache.delete(f"auth:{user_id}")

    elif req.fault_type == "token_expiry":
        pass

    elif req.fault_type == "cross_user_isolation":
        if not req.secondary_user_id:
            raise HTTPException(status_code=400, detail="secondary_user_id is REQUIRED for cross_user_isolation scenario.")
        USER_ROLES_DB[user_id] = RoleEnum.USER.value
        effective_cache_ttl = req.cache_ttl_seconds * req.time_scale_factor
        auth_cache.set(f"auth:{req.secondary_user_id}", RoleEnum.ADMIN.value, ttl_seconds=effective_cache_ttl)

    elif req.fault_type == "agent_session_revocation":
        USER_ROLES_DB[user_id] = RoleEnum.USER.value
        effective_cache_ttl = req.cache_ttl_seconds * req.time_scale_factor
        auth_cache.set(f"auth:{user_id}", RoleEnum.ADMIN.value, ttl_seconds=effective_cache_ttl)

    details = req.model_dump()
    details["fault_applied_monotonic"] = t_fault_applied
    record_audit_event(x_authtime_request_id, "FAULT_INJECTED", details, experiment_id=exp_id, trial_id=tr_id)

    return {
        "status": "SUCCESS",
        "fault_type": req.fault_type,
        "target_user": user_id,
        "fault_applied_monotonic": t_fault_applied,
    }


@router.post("/faults/reset", dependencies=[Depends(enforce_local_client)])
def reset_faults(
    x_authtime_request_id: str = Header(default="fault-reset"),
    x_authtime_experiment_id: Optional[str] = Header(default=None),
    x_authtime_trial_id: Optional[str] = Header(default=None),
):
    """Resets target authorization state (cache & roles) without destroying historical evidence."""
    auth_cache.clear()
    USER_ROLES_DB.clear()
    USER_ROLES_DB.update({
        "admin1": RoleEnum.ADMIN.value,
        "user1": RoleEnum.USER.value,
        "guest1": RoleEnum.GUEST.value,
        "svc1": RoleEnum.SERVICE_ACCOUNT.value,
    })
    record_audit_event(
        x_authtime_request_id,
        "FAULT_RESET",
        {"status": "RESET_COMPLETE"},
        experiment_id=x_authtime_experiment_id,
        trial_id=x_authtime_trial_id,
    )
    return {"status": "RESET_COMPLETE"}


@router.get("/events", dependencies=[Depends(enforce_local_client)])
def get_events(experiment_id: Optional[str] = None):
    """Retrieves evidence events for a specific experiment_id strictly."""
    if not experiment_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="experiment_id query parameter is REQUIRED for evidence event retrieval.",
        )
    filtered = [e for e in EVENT_STORE if e.get("experiment_id") == experiment_id]
    return {"events": filtered}


class RunExperimentRequest(BaseModel):
    fault_type: str = Field("stale_cache", pattern="^(stale_cache|role_revocation|token_expiry|agent_session_revocation|cross_user_isolation)$")
    time_scale: float = Field(1.0, gt=0.0, le=10.0)
    repetitions: int = Field(3, ge=1, le=20)
    target_url: str = Field("http://127.0.0.1:8000")


@router.post("/api/run-experiment", dependencies=[Depends(enforce_local_client)])
async def api_run_experiment(req: RunExperimentRequest):
    from authtime.controller.experiment import ExperimentController
    from authtime.scenarios.generator import ScenarioGenerator
    from authtime.reporting.generator import ReportGenerator

    controller = ExperimentController(req.target_url)
    if req.fault_type == "cross_user_isolation":
        scenario = ScenarioGenerator.generate_cross_user_isolation_scenario(
            user_a_id="admin1", user_b_id="user1", time_scale_factor=req.time_scale
        )
    else:
        scenario = ScenarioGenerator.generate_single_fault_scenario(
            fault_type=req.fault_type, target_user_id="admin1", time_scale_factor=req.time_scale
        )

    batch_run_id = f"RUN-{int(time.time())}"
    run_dir = os.path.join("reports", batch_run_id)
    os.makedirs(run_dir, exist_ok=True)

    results = []
    for i in range(req.repetitions):
        exp_id = f"EXP-{batch_run_id}-{i+1}"
        res = await controller.run_single_trial(exp_id, scenario)
        results.append(res)

    stats = controller.aggregate_trial_statistics(results)
    last_res = results[-1]

    md_content = ReportGenerator.generate_markdown_report(last_res, stats)
    html_content = ReportGenerator.generate_html_report(last_res, stats)
    json_content = ReportGenerator.generate_json_report(last_res, stats)

    md_path = os.path.join(run_dir, f"{last_res.experiment_id}_report.md")
    html_path = os.path.join(run_dir, f"{last_res.experiment_id}_report.html")
    json_path = os.path.join(run_dir, f"{last_res.experiment_id}_result.json")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(json_content)

    return {
        "status": "COMPLETED",
        "batch_run_id": batch_run_id,
        "repetitions": req.repetitions,
        "reports": {"markdown": md_path, "html": html_path, "json": json_path},
    }
