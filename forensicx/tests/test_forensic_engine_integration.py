"""Database integration tests for separately persisted forensic findings."""
from __future__ import annotations

import hashlib
from pathlib import Path

from forensicx.modules.cases.models import CaseModel
from forensicx.modules.evidence.models import Evidence, EvidenceStatus
from forensicx.modules.evidence.repository import EvidenceRepository
from forensicx.modules.forensic_engine.registry import AnalyzerRegistry
from forensicx.modules.forensic_engine.repository import ForensicAnalysisRepository
from forensicx.modules.forensic_engine.service import ForensicAnalysisService
from forensicx.platform.config import Settings
from forensicx.platform.database import configure_session_factory


def test_analysis_results_are_persisted_without_changing_evidence(tmp_path: Path) -> None:
    """Analysis writes only result rows in the request-owned transaction."""
    storage = tmp_path / "storage"
    file_path = storage / "cases" / "1" / "evidence" / "sample.pdf"
    file_path.parent.mkdir(parents=True)
    content = b"%PDF-1.4\n1 0 obj\n<< /Title (Unit Test) >>\n"
    file_path.write_bytes(content)
    settings = Settings(database_path=tmp_path / "forensicx.sqlite3", storage_path=storage, max_upload_size=1024, allowed_extensions=(".pdf",), jwt_secret="test", access_token_minutes=1, cors_origins=[], environment="test", log_level="WARNING", request_limit_per_minute=10)
    session = configure_session_factory(settings)()
    try:
        case = CaseModel(case_number="CASE-2026-0001", title="Test", description="Test", priority="low", status="open", lead_investigator="tester")
        session.add(case)
        session.flush()
        evidence = Evidence(case_id=case.id, original_filename="sample.pdf", stored_filename="sample.pdf", storage_path=str(file_path), file_extension=".pdf", mime_type="application/pdf", magic_type=None, file_size=len(content), md5=hashlib.md5(content).hexdigest(), sha1=hashlib.sha1(content).hexdigest(), sha256=hashlib.sha256(content).hexdigest(), uploaded_by="tester", status=EvidenceStatus.UPLOADED)
        session.add(evidence)
        session.flush()
        original_hash, original_status = evidence.sha256, evidence.status
        service = ForensicAnalysisService(EvidenceRepository(session), ForensicAnalysisRepository(session), AnalyzerRegistry(), storage)
        results = service.analyze(evidence.id, "tester")
        session.commit()
        assert len(results) >= 5
        assert evidence.sha256 == original_hash
        assert evidence.status == original_status
        assert len(ForensicAnalysisRepository(session).list_for_evidence(evidence.id, offset=0, limit=100)) == len(results)
    finally:
        session.close()
