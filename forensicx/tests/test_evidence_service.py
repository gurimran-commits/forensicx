"""Service tests for evidence validation, storage, and retrieval."""

from __future__ import annotations

import asyncio
from io import BytesIO
from pathlib import Path

from fastapi import UploadFile

from forensicx.modules.cases.models import CaseModel
from forensicx.modules.chain_of_custody.repository import ChainOfCustodyRepository
from forensicx.modules.chain_of_custody.service import ChainOfCustodyService
from forensicx.modules.evidence.repository import EvidenceRepository
from forensicx.modules.evidence.service import EvidenceService
from forensicx.modules.evidence.services.hashing import HashingService
from forensicx.modules.evidence.services.metadata import MetadataService
from forensicx.modules.evidence.services.storage import StorageService
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


def _upload(filename: str, content: bytes) -> UploadFile:
    return UploadFile(filename=filename, file=BytesIO(content))


def test_evidence_service_validates_uploads_and_retrieves_files(tmp_path: Path) -> None:
    """Validation does not store data; a valid upload is persisted under tmp_path."""
    settings = _settings(tmp_path)
    session = configure_session_factory(settings)()
    try:
        case = CaseModel(
            case_number="CASE-2026-0001",
            title="Evidence test",
            description="Evidence service test case.",
            priority="Low",
            status="open",
            lead_investigator="Analyst",
        )
        session.add(case)
        session.flush()
        service = EvidenceService(
            repository=EvidenceRepository(session),
            storage=StorageService(settings.storage_path),
            hashing=HashingService(),
            metadata=MetadataService(),
            custody_service=ChainOfCustodyService(ChainOfCustodyRepository(session)),
        )

        filename, extension, size = asyncio.run(service.validate_upload(_upload("note.txt", b"evidence bytes")))
        saved = asyncio.run(service.upload(case.id, "analyst", _upload("note.txt", b"evidence bytes")))
        fetched = service.get(saved.id)

        assert (filename, extension, size) == ("note.txt", ".txt", len(b"evidence bytes"))
        assert fetched.id == saved.id
        assert fetched.original_filename == "note.txt"
        assert Path(fetched.storage_path).is_file()
        assert Path(fetched.storage_path).read_bytes() == b"evidence bytes"
    finally:
        session.close()
