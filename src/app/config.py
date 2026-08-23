"""
Reference Application Configuration.
"""

import os


class Settings:
    SECRET_KEY: str = os.getenv("AUTHTIME_SECRET_KEY", "authtime_secret_key_for_testing_only_12345")
    ALGORITHM: str = os.getenv("AUTHTIME_ALGORITHM", "HS256")
    DEFAULT_JWT_TTL_SECONDS: int = int(os.getenv("AUTHTIME_JWT_TTL", "300"))
    DEFAULT_CACHE_TTL_SECONDS: float = float(os.getenv("AUTHTIME_CACHE_TTL", "60.0"))
    TARGET_HOST: str = os.getenv("AUTHTIME_TARGET_HOST", "127.0.0.1")
    TARGET_PORT: int = int(os.getenv("AUTHTIME_TARGET_PORT", "8000"))


settings = Settings()
