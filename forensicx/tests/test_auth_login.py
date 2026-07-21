"""Tests for username/password authentication."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from forensicx.modules.auth.api import LoginRequest, issue_development_token, login
from forensicx.modules.auth.models import User
from forensicx.platform.config import Settings
from forensicx.platform.database import configure_session_factory
from forensicx.platform.errors import ForensicXError
from forensicx.platform.security import hash_password, verify_access_token


def _settings(tmp_path: Path, environment: str = "test") -> Settings:
    return Settings(
        database_path=tmp_path / "forensicx.sqlite3",
        storage_path=tmp_path / "storage",
        max_upload_size=1024,
        allowed_extensions=(".pdf",),
        jwt_secret="test-secret",
        access_token_minutes=15,
        cors_origins=[],
        environment=environment,
        log_level="WARNING",
        request_limit_per_minute=10,
    )


def test_login_issues_a_jwt_for_valid_credentials(tmp_path: Path) -> None:
    """A persisted user can log in, while invalid credentials are rejected."""
    settings = _settings(tmp_path)
    session = configure_session_factory(settings)()
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=settings)))
    try:
        session.add(User(username="analyst", hashed_password=hash_password("correct horse battery staple"), roles=["cases:read"]))
        session.commit()
        response = asyncio.run(
            login(LoginRequest(username="analyst", password="correct horse battery staple"), request, session)
        )
        with pytest.raises(ForensicXError, match="Invalid username or password") as exc_info:
            asyncio.run(login(LoginRequest(username="analyst", password="wrong"), request, session))
    finally:
        session.close()

    assert response.token_type == "bearer"
    principal = verify_access_token(response.access_token, "test-secret")
    assert principal.subject == "analyst"
    assert principal.roles == frozenset({"cases:read"})
    assert exc_info.value.status_code == 401


def test_development_token_remains_unavailable_in_production(tmp_path: Path) -> None:
    """The development shortcut is not exposed by a production app."""
    settings = _settings(tmp_path, environment="production")
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=settings)))
    with pytest.raises(ForensicXError, match="disabled in production") as exc_info:
        asyncio.run(issue_development_token(request))
    assert exc_info.value.status_code == 404
