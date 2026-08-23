"""
Django Reference Authorization Target for AuthTime.
Runs via WSGI / ASGI bound strictly to 127.0.0.1:8002.
"""

import time
import jwt
from fastapi import FastAPI, Request, HTTPException, Depends
from pydantic import BaseModel

app = FastAPI(title="Django AuthTarget Replica")
JWT_SECRET = "authtime-django-secret-key-32-bytes!"

USER_ROLES_DB = {"admin1": "Admin", "user1": "User"}
AUTH_CACHE = {}


@app.post("/auth/login")
def login(data: dict):
    user_id = data.get("user_id", "admin1")
    role = USER_ROLES_DB.get(user_id, "User")
    token = jwt.encode({"sub": user_id, "role": role, "exp": int(time.time()) + 3600}, JWT_SECRET, algorithm="HS256")
    return {"access_token": token, "token_type": "bearer"}


@app.get("/admin/users")
def get_admin_users(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Token")
    token = auth_header.split(" ")[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid Token")

    user_id = decoded["sub"]
    now = time.monotonic()
    role = USER_ROLES_DB.get(user_id, "User")

    if user_id in AUTH_CACHE and AUTH_CACHE[user_id]["expires_at"] > now:
        role = AUTH_CACHE[user_id]["role"]

    if role != "Admin":
        raise HTTPException(status_code=403, detail="Permission Denied")

    return {"users": ["admin1", "user1"], "target": "Django Replica"}


@app.post("/faults/inject")
def inject_fault(data: dict):
    user_id = data.get("user_id", "admin1")
    new_role = data.get("new_role", "User")
    USER_ROLES_DB[user_id] = new_role
    if data.get("fault_type") == "stale_cache":
        AUTH_CACHE[user_id] = {"role": "Admin", "expires_at": time.monotonic() + data.get("cache_ttl_seconds", 30)}
    return {"status": "fault_injected"}


@app.post("/faults/reset")
def reset_state():
    global USER_ROLES_DB, AUTH_CACHE
    USER_ROLES_DB = {"admin1": "Admin", "user1": "User"}
    AUTH_CACHE = {}
    return {"status": "reset_complete"}
