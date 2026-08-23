"""
AuthTime Distributed Lab - JWT Authorization Lifecycle Handler.
"""

import os
import time
import uuid
import jwt
from typing import Dict, Any, Optional


class LabJWTHandler:
    """
    JWT Token Creator and Verifier for Distributed Authorization Lab.
    Supports role checking, short/long TTLs, and token versioning.
    """

    def __init__(self, secret: Optional[str] = None):
        self.secret = secret or os.getenv("JWT_SECRET") or f"lab-secret-{uuid.uuid4().hex}"
        self.algorithm = "HS256"

    def create_access_token(
        self,
        user_id: str,
        role: str,
        auth_version: int = 1,
        ttl_sec: float = 3600.0,
    ) -> str:
        """Create signed JWT access token with role and auth_version claims."""
        now = int(time.time())
        payload = {
            "sub": user_id,
            "role": role,
            "auth_ver": auth_version,
            "iat": now,
            "exp": now + int(ttl_sec),
            "jti": f"jti-{uuid.uuid4().hex[:12]}",
            "iss": "authtime-distributed-lab",
            "aud": "authtime-lab-replicas",
        }
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def verify_access_token(self, token: str) -> Dict[str, Any]:
        """Verify token signature, expiration, issuer, and audience."""
        try:
            payload = jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],
                audience="authtime-lab-replicas",
                issuer="authtime-distributed-lab",
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Token signature expired")
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid token: {str(e)}")
