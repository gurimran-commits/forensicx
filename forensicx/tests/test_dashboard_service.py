"""Service tests for dashboard summaries derived from live data."""

from __future__ import annotations

from pathlib import Path

from forensicx.modules.cases.models import CaseModel
from forensicx.modules.cases.repository import CaseRepository
from forensicx.modules.dashboard.repository import DashboardRepository
from forensicx.modules.dashboard.service import DashboardService
from forensicx.modules.evidence.models import Evidence, EvidenceStatus
from forensicx.modules.evidence.repository import EvidenceRepository
from forensicx.platform.config import Settings
from forensicx.platform.database import configure_session_factory
from forensicx.platform import model_registry as _model_registry


def _settings(tmp_path: Path) -> Settings:
    return Settings(tmp_path / "forensicx.sqlite3", tmp_path / "storage", 1024, (".txt",), "test", 1, [], "test", "WARNING", 10)


def test_dashboard_overview_aggregates_cases_and_evidence(tmp_path: Path) -> None:
    session = configure_session_factory(_settings(tmp_path))()
    try:
        case = CaseModel(
            case_number="CASE-2026-0001",
            title="Dashboard test",
            description="Test",
            priority="High",
            status="open",
            lead_investigator="Analyst",
        )
        session.add(case)
        session.flush()
        session.add(Evidence(case_id=case.id, original_filename="memory.bin", stored_filename="memory.bin", storage_path="/tmp/memory.bin", file_extension=".bin", mime_type="application/octet-stream", magic_type=None, file_size=1, md5="0" * 32, sha1="0" * 40, sha256="1" * 64, uploaded_by="Analyst", status=EvidenceStatus.ANALYZED))
        session.flush()
        service = DashboardService(DashboardRepository(CaseRepository(session), EvidenceRepository(session)))

        overview = service.overview(date_range="Last 7 days")

        assert overview.date_range == "Last 7 days"
        assert [card.value for card in overview.kpis] == ["1", "1", "1"]
        assert overview.evidence[0].label == "BIN"
        assert overview.recent_cases[0].case_number == case.case_number
    finally:
        session.close()
