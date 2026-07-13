"""Tests for the ForensicX dashboard REST module."""

from __future__ import annotations

from pathlib import Path

from forensicx.main import create_app
from forensicx.modules.dashboard.repository import DashboardRepository
from forensicx.modules.dashboard.service import DashboardService
from forensicx.platform.config import Settings
from forensicx.platform.database import get_session, initialize_database
from forensicx.platform.security import create_access_token, verify_access_token


def test_dashboard_service_returns_valid_overview(tmp_path: Path) -> None:
    """Dashboard service returns a validated overview from the repository."""
    database_path = tmp_path / "forensicx.sqlite3"
    settings = _settings(database_path)
    initialize_database(settings)
    with get_session() as session:
        overview = DashboardService(DashboardRepository(session)).overview()
        session.commit()
        assert overview.kpis[0].key == "active_cases"
        assert overview.ioc_matches[0].matches == 23
        assert overview.system_statuses[0].healthy is True


def test_security_token_round_trip() -> None:
    """Access tokens can be created and verified with roles intact."""
    token = create_access_token("analyst-1", ["dashboard:read"], "secret", 60)
    principal = verify_access_token(token, "secret")
    assert principal.subject == "analyst-1"
    assert "dashboard:read" in principal.roles


def test_app_registers_dashboard_route(tmp_path: Path) -> None:
    """Application factory registers the dashboard API route."""
    app = create_app(_settings(tmp_path / "forensicx.sqlite3"))
    paths = set(app.openapi()["paths"])
    assert "/api/v1/dashboard/overview" in paths
    assert "/api/v1/auth/dev-token" in paths
    assert "/api/v1/cases" in paths


def _settings(database_path: Path) -> Settings:
    """Create isolated test settings."""
    return Settings(
        database_path=database_path,
        jwt_secret="test-secret",
        access_token_minutes=5,
        cors_origins=["http://127.0.0.1:8765"],
        environment="development",
        log_level="CRITICAL",
        request_limit_per_minute=1000,
    )
