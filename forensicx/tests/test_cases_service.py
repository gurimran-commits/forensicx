"""Service tests for case creation, listing, and status changes."""

from __future__ import annotations

from pathlib import Path

from forensicx.modules.cases.repository import CaseRepository
from forensicx.modules.cases.schemas import CaseCreate
from forensicx.modules.cases.service import CaseService
from forensicx.platform.config import Settings
from forensicx.platform.database import configure_session_factory
from forensicx.platform import model_registry as _model_registry


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        database_path=tmp_path / "forensicx.sqlite3",
        storage_path=tmp_path / "storage",
        max_upload_size=1024,
        allowed_extensions=(".txt",),
        jwt_secret="test",
        access_token_minutes=1,
        cors_origins=[],
        environment="test",
        log_level="WARNING",
        request_limit_per_minute=10,
    )


def test_case_service_creates_lists_and_updates_status(tmp_path: Path) -> None:
    """Cases receive numbers, appear in filtered listings, and can change status."""
    session = configure_session_factory(_settings(tmp_path))()
    try:
        service = CaseService(CaseRepository(session))
        first = service.create_case(
            CaseCreate(
                title="Credential investigation",
                description="Investigate suspicious credential access.",
                priority="High",
                lead_investigator="Analyst One",
            )
        )
        service.create_case(
            CaseCreate(
                title="Malware triage",
                description="Analyze the reported malware sample.",
                priority="Medium",
                lead_investigator="Analyst Two",
            )
        )

        listed = service.list_cases(status="open", search="credential", sort="case_number", limit=10, offset=0)
        updated = service.update_status(first.case_number, "investigating")

        assert first.case_number.endswith("0001")
        assert listed.total == 1
        assert [item.case_number for item in listed.items] == [first.case_number]
        assert updated.status == "investigating"
        assert service.get_case(first.case_number).status == "investigating"
    finally:
        session.close()
