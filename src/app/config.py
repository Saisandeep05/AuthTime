"""
Reference Application Configuration.
"""


class Settings:
    SECRET_KEY: str = "authtime_secret_key_for_testing_only_12345"
    ALGORITHM: str = "HS256"
    DEFAULT_JWT_TTL_SECONDS: int = 300
    DEFAULT_CACHE_TTL_SECONDS: float = 60.0
    TARGET_HOST: str = "127.0.0.1"
    TARGET_PORT: int = 8000


settings = Settings()
