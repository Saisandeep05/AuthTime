"""
Reference Auth Target configuration.
"""

from pydantic import ConfigDict
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = ConfigDict(env_file=".env", extra="ignore")

    TARGET_HOST: str = "127.0.0.1"
    TARGET_PORT: int = 8000
    TEST_ENVIRONMENT: bool = True

    JWT_SECRET: str = "authtime-local-secret-key-change-in-prod-12345"
    JWT_ALGORITHM: str = "HS256"
    DEFAULT_JWT_TTL_SECONDS: int = 300

    DEFAULT_CACHE_TTL_SECONDS: int = 60
    CACHE_ENABLED: bool = True


settings = Settings()
