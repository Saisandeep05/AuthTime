"""
Reference Application API Routes & Fault Injection Controller.
"""

import os
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Header, HTTPException, Request, Depends, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import time
from datetime import datetime, timezone

from app.auth.jwt import create_access_token, decode_access_token
from app.rbac.roles import USER_ROLES_DB, has_permission, RoleEnum
from app.cache.ttl_cache import auth_cache

router = APIRouter()

# Structured Audit Event Store
EVENT_STORE: List[Dict[str, Any]] = []


@router.get("/", response_class=HTMLResponse)
def get_dashboard():
    static_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "index.html")
    if os.path.exists(static_path):
        with open(static_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>AuthTime Control Center Target Server Active</h1>"



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


class RunExperimentRequest(BaseModel):
    fault_type: str = "stale_cache"
    time_scale: float = 1.0
    repetitions: int = 3
    target_url: str = "http://127.0.0.1:8000"


@router.post("/api/run-experiment", dependencies=[Depends(enforce_local_client)])
async def api_run_experiment(req: RunExperimentRequest):
    from authtime.controller.experiment import ExperimentController
    from authtime.scenarios.generator import ScenarioGenerator
    from authtime.reporting.generator import ReportGenerator
    from authtime.history.tracker import ExposureHistoryTracker

    controller = ExperimentController(req.target_url)
    if req.fault_type == "cross_user_isolation":
        scenario = ScenarioGenerator.generate_cross_user_isolation_scenario(
            user_a_id="admin1", user_b_id="user1", time_scale_factor=req.time_scale
        )
    else:
        scenario = ScenarioGenerator.generate_single_fault_scenario(
            fault_type=req.fault_type, target_user_id="admin1", time_scale_factor=req.time_scale
        )

    results = []
    for i in range(req.repetitions):
        exp_id = f"EXP-WEB-{int(time.time())}-{i+1}"
        res = await controller.run_single_trial(exp_id, scenario)
        results.append(res)

    stats = controller.aggregate_trial_statistics(results)
    last_res = results[-1]

    tracker = ExposureHistoryTracker()
    tracker.record_run(last_res)

    os.makedirs("reports", exist_ok=True)
    md_content = ReportGenerator.generate_markdown_report(last_res, stats)
    html_content = ReportGenerator.generate_html_report(last_res, stats)
    json_content = ReportGenerator.generate_json_report(last_res, stats)

    with open("reports/sample_report.md", "w", encoding="utf-8") as f:
        f.write(md_content)
    with open("reports/sample_report.html", "w", encoding="utf-8") as f:
        f.write(html_content)
    with open("reports/results.json", "w", encoding="utf-8") as f:
        f.write(json_content)

    return {
        "status": "SUCCESS",
        "estimated_exposure_sec": last_res.exposure_metrics.estimated_exposure_sec,
        "precision_sec": last_res.exposure_metrics.precision_sec,
        "severity_score": last_res.finding.severity_score,
        "severity_label": last_res.finding.severity_label,
        "root_cause": last_res.finding.root_cause,

        "jitter_ms": last_res.exposure_metrics.scheduler_jitter_ms,
        "probes": [{"rel_sec": p.offset_target, "allowed": (p.actual_decision == "ALLOW"), "status": p.http_status} for p in last_res.probes],

        "stats": {
            "mean": stats.get("mean_exposure_sec", 0.0) if isinstance(stats, dict) else getattr(stats, "mean_exposure_sec", 0.0),
            "std_dev": stats.get("std_dev_sec", 0.0) if isinstance(stats, dict) else getattr(stats, "std_dev_sec", 0.0),
            "min": stats.get("min_exposure_sec", 0.0) if isinstance(stats, dict) else getattr(stats, "min_exposure_sec", 0.0),
            "max": stats.get("max_exposure_sec", 0.0) if isinstance(stats, dict) else getattr(stats, "max_exposure_sec", 0.0)
        }

    }



@router.get("/api/history")
def get_history():
    from authtime.history.tracker import ExposureHistoryTracker
    tracker = ExposureHistoryTracker()
    return {"history": tracker.load_history()}

