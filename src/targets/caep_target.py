"""
OpenID CAEP (Continuous Access Evaluation Profile) Receiver & Target Replica.
Processes SSF/CAEP Push Revocation Events over HTTP loopback.
"""

import time
import jwt
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel

app = FastAPI(title="CAEP Push Revocation Target Replica")
JWT_SECRET = "authtime-caep-secret-key-32-bytes!"

USER_SESSIONS = {
    "admin1": {"session_id": "sess-admin1-99", "role": "Admin", "active": True, "revoked_at": None}
}


class CAEPEvent(BaseModel):
    event_type: str  # e.g., "https://schemas.openid.net/secevent/caep/event-type/session-revocation"
    subject: str  # user_id or session_id
    event_timestamp: float


@app.post("/caep/events")
def handle_caep_event(event: CAEPEvent):
    """Handles push revocation events from Identity Provider (IdP)."""
    if event.subject in USER_SESSIONS:
        USER_SESSIONS[event.subject]["active"] = False
        USER_SESSIONS[event.subject]["revoked_at"] = event.event_timestamp
        USER_SESSIONS[event.subject]["role"] = "Revoked"
    return {"status": "caep_event_processed", "subject": event.subject, "event_type": event.event_type}


@app.get("/caep/protected")
def caep_protected_resource(request: Request, user_id: str = "admin1"):
    sess = USER_SESSIONS.get(user_id)
    if not sess or not sess["active"] or sess["role"] != "Admin":
        raise HTTPException(status_code=403, detail="CAEP Session Revoked")
    return {"status": "success", "user_id": user_id, "data": "Confidential CAEP Resource"}
