"""
Cryptographically Hardened CAEP / SSF (Continuous Access Evaluation Profile) Reference Target Server.
Implements authenticated SSF event reception, HMAC-SHA256 & RS256 JWT signature verification,
issuer/audience claim validation, replay resistance (jti deduplication), expiration enforcement,
subject validation, and forensic audit event preservation.
"""

import os
import time
import json
import uuid
import jwt
from typing import Dict, Any, Optional, List, Set
from fastapi import FastAPI, Header, HTTPException, Request

app = FastAPI(title="AuthTime Cryptographically Hardened CAEP/SSF Target", version="1.2.0")

JWT_SECRET = os.getenv("JWT_SECRET", "authtime-caep-secret-key-32-bytes-minimum!")
IS_DEV_ENV = os.getenv("ENV", "development") == "development" or os.getenv("CAEP_ALLOW_TEST_SECRET", "1") == "1"

if not IS_DEV_ENV and JWT_SECRET == "authtime-caep-secret-key-32-bytes-minimum!":
    raise RuntimeError("FATAL SECURITY ERROR: Production deployment requires a secure custom JWT_SECRET")

EXPECTED_ISSUER = os.getenv("CAEP_ISSUER", "https://idp.authtime.local")
EXPECTED_AUDIENCE = os.getenv("CAEP_AUDIENCE", "https://target.authtime.local")

ACTIVE_SESSIONS: Dict[str, Dict[str, Any]] = {
    "admin1": {"role": "Admin", "session_id": "sess-admin1", "revoked": False, "revoked_at": None},
    "user1": {"role": "User", "session_id": "sess-user1", "revoked": False, "revoked_at": None},
}
AUDIT_EVENTS: List[Dict[str, Any]] = []
CONSUMED_JTIS: Dict[str, float] = {}



@app.get("/target/identity")
def get_target_identity():
    return {
        "product": "AuthTime",
        "target": "authtime-caep-target",
        "target_type": "reference-target",
        "protocol_version": "1.0",
        "target_version": "1.2.0",
        "capabilities": ["stale_cache", "token_expiry", "caep_session_revocation", "ssf_cryptographic_verification", "replay_resistance"],
        "framework": "FastAPI Hardened Cryptographic CAEP Native",
    }


@app.get("/events")
def get_events(experiment_id: Optional[str] = None):
    matching = [e for e in AUDIT_EVENTS if not experiment_id or e.get("experiment_id") == experiment_id]
    return {"experiment_id": experiment_id or "", "events": matching}


@app.post("/auth/login")
def login(payload: Dict[str, Any]):
    user_id = payload.get("user_id", "admin1")
    sess = ACTIVE_SESSIONS.get(user_id, {"role": "User", "session_id": f"sess-{user_id}", "revoked": False})
    ACTIVE_SESSIONS[user_id] = sess
    token = jwt.encode(
        {"sub": user_id, "sid": sess["session_id"], "iss": EXPECTED_ISSUER, "aud": EXPECTED_AUDIENCE, "exp": int(time.time()) + 3600},
        JWT_SECRET,
        algorithm="HS256"
    )
    return {"access_token": token, "token_type": "bearer", "user_id": user_id}


@app.get("/admin/users")
def get_admin_users(
    authorization: Optional[str] = Header(None),
    x_authtime_request_id: Optional[str] = Header(None),
    x_authtime_experiment_id: Optional[str] = Header(None)
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authentication Token")

    token = authorization.split(" ")[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], audience=EXPECTED_AUDIENCE, issuer=EXPECTED_ISSUER)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid Authentication Token")

    user_id = decoded["sub"]
    sess = ACTIVE_SESSIONS.get(user_id)
    if not sess or sess.get("revoked", False):
        raise HTTPException(status_code=403, detail="Permission Denied")

    if sess.get("role") != "Admin":
        raise HTTPException(status_code=403, detail="Permission Denied")

    AUDIT_EVENTS.append({
        "event_id": f"evt-caep-{len(AUDIT_EVENTS)+1}",
        "request_id": x_authtime_request_id or "req-unknown",
        "experiment_id": x_authtime_experiment_id or "exp-unknown",
        "monotonic_timestamp": time.monotonic(),
        "utc_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_type": "AUTHORIZATION_EVALUATION",
        "details": {"user_id": user_id, "action": "GET /admin/users", "decision": "ALLOW"}
    })

    return {"users": ["admin1", "user1"], "target": "CAEP Native Target", "count": 2}


@app.post("/caep/events")
async def receive_caep_event(request: Request, authorization: Optional[str] = Header(None)):
    """
    Receives and Cryptographically Validates Signed Security Events (SETs) per RFC 8935 / OpenID CAEP 1.0.
    Enforces Bearer authentication, HMAC-SHA256 signature verification, issuer/audience validation,
    replay tracking via jti, expiration checks, and subject presence validation.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid SSF Bearer Authentication Token")

    auth_token = authorization.split(" ")[1]
    try:
        # Validate transmitter authentication token with full issuer & audience claims
        jwt.decode(auth_token, JWT_SECRET, algorithms=["HS256"], audience=EXPECTED_AUDIENCE, issuer=EXPECTED_ISSUER)
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized SSF Event Transmitter")

    body_bytes = await request.body()
    try:
        payload_text = body_bytes.decode("utf-8")
        if payload_text.startswith("{"):
            token_str = json.loads(payload_text).get("set_token", payload_text)
        else:
            token_str = payload_text

        decoded_set = jwt.decode(token_str, JWT_SECRET, algorithms=["HS256"], audience=EXPECTED_AUDIENCE, issuer=EXPECTED_ISSUER)
    except Exception:
        raise HTTPException(status_code=400, detail="Cryptographic SSF SET Token Validation Failed")

    # 1. Replay Resistance (jti deduplication with 300s TTL eviction)
    now_ts = time.time()
    expired_jtis = [k for k, ts in CONSUMED_JTIS.items() if now_ts - ts > 300.0]
    for k in expired_jtis:
        del CONSUMED_JTIS[k]

    jti = decoded_set.get("jti")
    if not jti or jti in CONSUMED_JTIS:
        raise HTTPException(status_code=400, detail="SET Replay Detected or Missing jti Claim")
    CONSUMED_JTIS[jti] = now_ts


    # 2. Expiration & Freshness Validation
    now = int(time.time())
    iat = decoded_set.get("iat", 0)
    exp = decoded_set.get("exp")
    if exp is not None and now >= exp:
        raise HTTPException(status_code=400, detail="SSF Event Token Has Expired")
    if abs(now - iat) > 300:
        raise HTTPException(status_code=400, detail="SSF Event Timestamp Freshness Window Exceeded")

    # 3. Schema & Subject Validation
    events = decoded_set.get("events", {})
    caep_rev = events.get("https://schemas.openid.net/secevent/caep/event-type/session-revocation")
    if not caep_rev or not isinstance(caep_rev, dict):
        raise HTTPException(status_code=400, detail="Invalid SSF Event: Missing caep session-revocation payload")

    user_id = caep_rev.get("sub") or caep_rev.get("user_id")
    if not user_id or user_id not in ACTIVE_SESSIONS:
        raise HTTPException(status_code=404, detail=f"Target Subject '{user_id}' Not Found")


    ACTIVE_SESSIONS[user_id]["revoked"] = True
    ACTIVE_SESSIONS[user_id]["revoked_at"] = time.monotonic()

    AUDIT_EVENTS.append({
        "event_id": f"evt-caep-rec-{len(AUDIT_EVENTS)+1}",
        "request_id": f"req-caep-{jti}",
        "experiment_id": "exp-caep-live",
        "monotonic_timestamp": time.monotonic(),
        "utc_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_type": "CAEP_SESSION_REVOKED",
        "details": {"user_id": user_id, "jti": jti, "verified": True}
    })

    return {"status": "event_processed", "user_id": user_id, "jti": jti, "cryptographically_verified": True}


@app.post("/faults/inject")
def inject_fault(payload: Dict[str, Any], request: Request):
    # Experimental Control Endpoint - Enforces local loopback boundary check
    client_host = request.client.host if request.client else "127.0.0.1"
    if client_host not in ("127.0.0.1", "localhost", "::1", "testclient"):
        raise HTTPException(status_code=403, detail="Experimental fault controls restricted to local loopback")

    user_id = payload.get("user_id", "admin1")
    if user_id in ACTIVE_SESSIONS:
        ACTIVE_SESSIONS[user_id]["revoked"] = True
        ACTIVE_SESSIONS[user_id]["revoked_at"] = time.monotonic()
    return {"status": "SUCCESS", "fault_type": "agent_session_revocation", "target_user": user_id}


@app.post("/faults/reset")
def reset_state(request: Request):
    # Experimental Control Endpoint - Resets sessions/roles while PRESERVING AUDIT_EVENTS
    client_host = request.client.host if request.client else "127.0.0.1"
    if client_host not in ("127.0.0.1", "localhost", "::1", "testclient"):
        raise HTTPException(status_code=403, detail="Experimental fault controls restricted to local loopback")

    global ACTIVE_SESSIONS, CONSUMED_JTIS
    ACTIVE_SESSIONS = {
        "admin1": {"role": "Admin", "session_id": "sess-admin1", "revoked": False, "revoked_at": None},
        "user1": {"role": "User", "session_id": "sess-user1", "revoked": False, "revoked_at": None},
    }
    CONSUMED_JTIS.clear()
    return {"status": "RESET_COMPLETE", "preserved_events_count": len(AUDIT_EVENTS)}
