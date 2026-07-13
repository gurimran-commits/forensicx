"""Tests for the ForensicX case management module."""

from __future__ import annotations

from pathlib import Path

import pytest

from forensicx.modules.cases.repository import CaseRepository
from forensicx.modules.cases.schemas import CaseCreate
from forensicx.modules.cases.service import CaseService
from forensicx.platform.config import Settings
from forensicx.platform.database import get_session, initialize_database
from forensicx.platform.errors import ForensicXError


def test_case_service_creates_lists_and_updates_status(tmp_path: Path) -> None:
    """Case service supports the core lifecycle through the repository."""
    initialize_database(_settings(tmp_path / "forensicx.sqlite3"))
    with get_session() as session:
        service = CaseService(CaseRepository(session))
        created = service.create_case(
            CaseCreate(
                title="Corporate endpoint intrusion",
                description="Initial triage found credential theft indicators on three endpoints.",
                priority="High",
                lead_investigator="Gurimran Singh",
            )
        )
        listed = service.list_cases(status=None, search="endpoint", sort="created_at", limit=10, offset=0)
        updated = service.update_status(created.case_number, "investigating")
        session.commit()
    assert created.case_number.startswith("CASE-")
    assert listed.total == 1
    assert listed.items[0].title == "Corporate endpoint intrusion"
    assert updated.status == "investigating"


def test_case_service_raises_for_missing_case(tmp_path: Path) -> None:
    """Missing cases raise a typed application exception."""
    initialize_database(_settings(tmp_path / "forensicx.sqlite3"))
    with get_session() as session:
        service = CaseService(CaseRepository(session))
        with pytest.raises(ForensicXError) as error:
            service.get_case("CASE-2026-9999")
    assert error.value.status_code == 404


def _settings(database_path: Path) -> Settings:
    """Create isolated test settings."""
    return Settings(
        database_path=database_path,
        jwt_secret="test-secret",
        access_token_minutes=5,
        cors_origins=["http://127.0.0.1:8770"],
        environment="development",
        log_level="CRITICAL",
        request_limit_per_minute=1000,
    )
