"""
Business logic for evidence management.
"""

from pathlib import Path

from fastapi import UploadFile
from sqlalchemy.orm import Session

from forensicx.modules.evidence.models import (
    Evidence,
    EvidenceStatus,
)
from forensicx.modules.evidence.repository import EvidenceRepository
from forensicx.modules.evidence.services.hashing import HashingService
from forensicx.modules.evidence.services.metadata import MetadataService
from forensicx.modules.evidence.services.storage import StorageService
from forensicx.modules.evidence.services.validator import EvidenceValidator

class EvidenceService:
    """Business logic for evidence operations."""

    def __init__(
        self,
        session: Session,
        storage_root: Path,
    ) -> None:

        self._repository = EvidenceRepository(session)

        self._storage = StorageService(storage_root)

        self._hashing = HashingService()

        self._metadata = MetadataService()

    async def upload(
        self,
        case_id: str,
        uploaded_by: str,
        upload: UploadFile,
        description: str | None = None,
        tags: str | None = None,
    ) -> Evidence:
        """Upload and register new evidence."""

        await EvidenceValidator.validate(upload)

        saved_path, stored_filename = self._storage.save(
            case_id,
            upload,
        )

        md5, sha1, sha256 = self._hashing.from_path(saved_path)

        existing = self._repository.get_by_sha256(sha256)

        if existing:
            return existing

        metadata = self._metadata.extract(saved_path)

        evidence = Evidence(
            case_id=case_id,
            original_filename=upload.filename or "",
            stored_filename=stored_filename,
            storage_path=str(saved_path),
            file_extension=metadata.extension,
            mime_type=metadata.mime_type,
            magic_type=None,
            file_size=metadata.size,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            uploaded_by=uploaded_by,
            description=description,
            tags=tags,
            status=EvidenceStatus.UPLOADED,
        )

        return self._repository.create(evidence)

    def get(self, evidence_id: str):
        """Return evidence by ID."""
        return self._repository.get_by_id(evidence_id)

    def list_case_evidence(self, case_id: str):
        """Return all evidence belonging to a case."""
        return self._repository.list_by_case(case_id)

    def delete(self, evidence_id: str):
        """Delete evidence."""
        evidence = self._repository.get_by_id(evidence_id)

        if evidence is None:
            return None

        self._repository.delete(evidence)

        return evidence
