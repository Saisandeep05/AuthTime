"""
Django Reference Authorization Target for AuthTime.
Runs a native Django WSGI application bound strictly to 127.0.0.1:8002.
"""

import os
import sys
import time
import json
import uuid
import jwt
import django
from django.conf import settings
from django.http import JsonResponse, HttpResponse
from django.urls import path
from django.core.wsgi import get_wsgi_application

# Ephemeral startup secret if JWT_SECRET environment variable is not explicitly provided
JWT_SECRET = os.getenv("JWT_SECRET") or f"ephemeral-{uuid.uuid4().hex}"
DEBUG_MODE = os.getenv("AUTHTIME_DEBUG", "false").lower() == "true"

# Configure Minimal In-Memory Django Settings
if not settings.configured:
    settings.configure(
        DEBUG=DEBUG_MODE,
        SECRET_KEY=JWT_SECRET,
        ROOT_URLCONF=__name__,
        ALLOWED_HOSTS=["127.0.0.1", "localhost", "testclient"],
        MIDDLEWARE=[
            "django.middleware.common.CommonMiddleware",
        ],
    )
    django.setup()

# In-memory target state
USER_ROLES_DB = {"admin1": "Admin", "user1": "User", "guest1": "Guest", "svc1": "ServiceAccount"}
ALLOWED_ROLES = {"Admin", "User", "Guest", "ServiceAccount"}
AUTH_CACHE = {}
AUDIT_EVENTS = []


def enforce_loopback_security(request) -> bool:
    remote_addr = request.META.get("REMOTE_ADDR", "127.0.0.1")
    return remote_addr in ("127.0.0.1", "localhost", "::1")


def login_view(request):
    if request.method != "POST":
        return JsonResponse({"detail": "Method Not Allowed"}, status=405)
    try:
        body = json.loads(request.body.decode("utf-8")) if request.body else {}
    except Exception:
        body = {}
    user_id = body.get("user_id", "admin1")
    role = USER_ROLES_DB.get(user_id, "User")
    token = jwt.encode({"sub": user_id, "role": role, "exp": int(time.time()) + 3600}, JWT_SECRET, algorithm="HS256")
    return JsonResponse({"access_token": token, "token_type": "bearer", "user_id": user_id, "role": role})


def get_admin_users_view(request):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return JsonResponse({"detail": "Missing Token"}, status=401)
    token = auth_header.replace("Bearer ", "").strip()
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return JsonResponse({"detail": "Invalid Token"}, status=401)

    user_id = decoded["sub"]
    now = time.monotonic()

    cached = AUTH_CACHE.get(f"auth:{user_id}")
    if cached and cached["expires_at"] > now:
        role = cached["role"]
    else:
        role = USER_ROLES_DB.get(user_id, "User")

    AUDIT_EVENTS.append({
        "event_id": f"evt-django-{len(AUDIT_EVENTS)+1}",
        "request_id": request.headers.get("X-AuthTime-Request-ID", "req-unknown"),
        "experiment_id": request.headers.get("X-AuthTime-Experiment-ID", "exp-unknown"),
        "monotonic_timestamp": now,
        "utc_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_type": "AUTHORIZATION_EVALUATION",
        "details": {"user_id": user_id, "action": "GET /admin/users", "decision": "ALLOW" if role == "Admin" else "DENY"}
    })

    if role != "Admin":
        return JsonResponse({"detail": "Permission Denied"}, status=403)

    return JsonResponse({"users": ["admin1", "user1"], "target": "Django Native Replica", "count": 2})


def inject_fault_view(request):
    if not enforce_loopback_security(request):
        return JsonResponse({"detail": "Safety Error: Fault injection restricted to local loopback"}, status=403)
    if request.method != "POST":
        return JsonResponse({"detail": "Method Not Allowed"}, status=405)
    try:
        body = json.loads(request.body.decode("utf-8")) if request.body else {}
    except Exception:
        body = {}
    user_id = body.get("user_id", "admin1")
    new_role = body.get("new_role", "User")
    if new_role not in ALLOWED_ROLES:
        return JsonResponse({"detail": f"Invalid role '{new_role}'. Must be one of {sorted(list(ALLOWED_ROLES))}"}, status=400)

    USER_ROLES_DB[user_id] = new_role
    if body.get("fault_type") == "stale_cache":
        AUTH_CACHE[f"auth:{user_id}"] = {
            "role": "Admin",
            "expires_at": time.monotonic() + body.get("cache_ttl_seconds", 30.0),
        }
    return JsonResponse({"status": "SUCCESS", "fault_type": body.get("fault_type"), "target_user": user_id})


def reset_state_view(request):
    if not enforce_loopback_security(request):
        return JsonResponse({"detail": "Safety Error: State reset restricted to local loopback"}, status=403)
    global USER_ROLES_DB, AUTH_CACHE
    USER_ROLES_DB = {"admin1": "Admin", "user1": "User", "guest1": "Guest", "svc1": "ServiceAccount"}
    AUTH_CACHE = {}
    return JsonResponse({"status": "RESET_COMPLETE", "preserved_events_count": len(AUDIT_EVENTS)})



def target_identity_view(request):
    return JsonResponse({
        "product": "AuthTime",
        "target": "authtime-django-target",
        "target_type": "reference-target",
        "protocol_version": "1.0",
        "target_version": "1.0.0",
        "capabilities": ["stale_cache", "token_expiry", "rbac_re-eval", "cross_user_isolation"],
        "framework": "Django Native",
    })


def get_events_view(request):
    exp_id = request.GET.get("experiment_id", "")
    matching = [e for e in AUDIT_EVENTS if not exp_id or e.get("experiment_id") == exp_id]
    return JsonResponse({"experiment_id": exp_id, "events": matching})


urlpatterns = [
    path("target/identity", target_identity_view),
    path("events", get_events_view),
    path("auth/login", login_view),
    path("admin/users", get_admin_users_view),
    path("faults/inject", inject_fault_view),
    path("faults/reset", reset_state_view),
]


app = get_wsgi_application()

if __name__ == "__main__":
    from wsgiref.simple_server import make_server
    print("[*] Starting Native Django Reference Target on http://127.0.0.1:8002...")
    httpd = make_server("127.0.0.1", 8002, app)
    httpd.serve_forever()
