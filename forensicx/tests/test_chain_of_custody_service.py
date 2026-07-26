"""Service tests for chain-of-custody event recording and retrieval."""

from __future__ import annotations

from pathlib import Path

import pytest

from forensicx.modules.cases.models import CaseModel
from forensicx.modules.chain_of_custody.repository import ChainOfCustodyRepository
from forensicx.modules.chain_of_custody.schemas import CustodyCreate
from forensicx.modules.chain_of_custody.service import ChainOfCustodyService
from forensicx.modules.evidence.models import Evidence, EvidenceStatus
from forensicx.platform.config import Settings
from forensicx.platform.database import configure_session_factory
from forensicx.platform.errors import ForensicXError
from forensicx.platform import model_registry as _model_registry


def _settings(tmp_path: Path) -> Settings:
    return Settings(tmp_path / "forensicx.sqlite3", tmp_path / "storage", 1024, (".txt",), "test", 1, [], "test", "WARNING", 10)


def test_custody_service_records_lists_and_reads_events(tmp_path: Path) -> None:
    session = configure_session_factory(_settings(tmp_path))()
    try:
        case = CaseModel(
            case_number="CASE-2026-0001",
            title="Custody test",
            description="Test",
            priority="Low",
            status="open",
            lead_investigator="Analyst",
        )
        session.add(case)
        session.flush()
        evidence = Evidence(case_id=case.id, original_filename="note.txt", stored_filename="note.txt", storage_path="/tmp/note.txt", file_extension=".txt", mime_type="text/plain", magic_type=None, file_size=1, md5="0" * 32, sha1="0" * 40, sha256="0" * 64, uploaded_by="Analyst", status=EvidenceStatus.UPLOADED)
        session.add(evidence)
        session.flush()
        service = ChainOfCustodyService(ChainOfCustodyRepository(session))

        recorded = service.record_event(CustodyCreate(evidence_id=evidence.id, action="verified", performed_by="Analyst", location="Lab", notes="Hash verified"))
        history = service.list_events(evidence.id, limit=10, offset=0)

        assert service.get_event(recorded.id).action == "verified"
        assert history.total == 1
        assert history.items[0].notes == "Hash verified"
        with pytest.raises(ForensicXError, match="Custody event not found"):
            service.get_event(999)
    finally:
        session.close()
