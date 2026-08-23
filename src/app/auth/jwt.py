"""
JWT Token Utilities for Reference Application.
"""

import time
import jwt
from typing import Dict, Any, Optional
from app.config import settings


def create_access_token(user_id: str, role: str, ttl_seconds: Optional[int] = None) -> str:
    ttl = ttl_seconds if ttl_seconds is not None else settings.DEFAULT_JWT_TTL_SECONDS
    now = time.time()
    payload = {
        "sub": user_id,
        "role": role,
        "iat": int(now),
        "exp": int(now + ttl),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
