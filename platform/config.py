"""Runtime configuration for ForensicX."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """Application settings loaded from environment variables."""

    database_path: Path

    storage_path: Path

    max_upload_size: int

    allowed_extensions: tuple[str, ...]

    jwt_secret: str

    access_token_minutes: int

    cors_origins: list[str]

    environment: str

    log_level: str

    request_limit_per_minute: int


def _required_secret() -> str:
    """Return the configured JWT secret or a generated development secret."""
    configured = os.getenv("FORENSICX_JWT_SECRET")
    if configured:
        return configured
    if os.getenv("FORENSICX_ENV", "development").lower() == "production":
        raise RuntimeError("FORENSICX_JWT_SECRET must be set in production")
    return os.urandom(32).hex()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Load settings once for the process."""
    raw_origins = os.getenv("FORENSICX_CORS_ORIGINS", "http://127.0.0.1:8765,http://127.0.0.1:8770")
    return Settings(
        database_path=Path(os.getenv("FORENSICX_DATABASE_PATH", "data/forensicx.sqlite3")),
        jwt_secret=_required_secret(),
        access_token_minutes=int(os.getenv("FORENSICX_ACCESS_TOKEN_MINUTES", "60")),
        cors_origins=[origin.strip() for origin in raw_origins.split(",") if origin.strip()],
        environment=os.getenv("FORENSICX_ENV", "development").lower(),
        log_level=os.getenv("FORENSICX_LOG_LEVEL", "INFO").upper(),
        request_limit_per_minute=int(os.getenv("FORENSICX_RATE_LIMIT_PER_MINUTE", "120")),
        storage_path=Path(
            os.getenv(
                "FORENSICX_STORAGE_PATH",
                "storage",
            )
        ),

        max_upload_size=int(
            os.getenv(
                "FORENSICX_MAX_UPLOAD_SIZE",
                str(1024 * 1024 * 1024),
            )
        ),

        allowed_extensions=tuple(
            ext.strip().lower()
            for ext in os.getenv(
                "FORENSICX_ALLOWED_EXTENSIONS",
                ".zip,.7z,.rar,.pcap,.pcapng,.img,.iso,.e01,.raw,.mem,.dmp,.bin,.exe,.dll,.pdf,.docx,.xlsx,.csv,.json,.xml,.txt,.jpg,.jpeg,.png",
            ).split(",")
        ),
    )
