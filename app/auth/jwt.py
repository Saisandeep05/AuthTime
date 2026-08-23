"""
JWT token generation and validation utilities for the Reference Auth Target.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
import jwt
from app.config import settings


def create_jwt_token(
    user_id: str,
    role: str,
    ttl_seconds: Optional[int] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    ttl = ttl_seconds if ttl_seconds is not None else settings.DEFAULT_JWT_TTL_SECONDS
    now = datetime.now(timezone.utc)
    exp = now + timedelta(seconds=ttl)

    payload = {
        "sub": user_id,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_jwt_token(token: str) -> Dict[str, Any]:
    return jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
        options={"verify_exp": True},
    )


def verify_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return decode_jwt_token(token)
    except (jwt.PyJWTError, ValueError):
        return None
