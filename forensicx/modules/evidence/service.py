"""Business logic for evidence management."""

import logging
from pathlib import Path

from fastapi import UploadFile
from forensicx.modules.chain_of_custody.schemas import CustodyCreate
from forensicx.modules.chain_of_custody.service import ChainOfCustodyService

from forensicx.modules.evidence.models import (
    Evidence,
    EvidenceStatus,
)
from forensicx.modules.evidence.repository import EvidenceRepository
from forensicx.modules.evidence.services.hashing import HashingService
from forensicx.modules.evidence.services.metadata import MetadataService
from forensicx.modules.evidence.services.storage import StorageService
from forensicx.modules.evidence.services.validator import EvidenceValidator
from forensicx.platform.errors import ForensicXError


LOGGER = logging.getLogger(__name__)

class EvidenceService:
    """Business logic for evidence operations."""

    def __init__(
        self,
        repository: EvidenceRepository,
        storage: StorageService,
        hashing: HashingService,
        metadata: MetadataService,
        custody_service: ChainOfCustodyService,
        validator: EvidenceValidator,
    ) -> None:
        self._repository = repository
        self._storage = storage
        self._hashing = hashing
        self._metadata = metadata
        self._custody = custody_service
        self._validator = validator

    async def upload(
        self,
        case_id: int,
        uploaded_by: str,
        upload: UploadFile,
        description: str | None = None,
        tags: str | None = None,
    ) -> Evidence:
        """Upload and register new evidence."""

        await self._validator.validate(upload)

        saved_path, stored_filename = self._storage.save(
            str(case_id),
            upload,
        )

        md5, sha1, sha256 = self._hashing.from_path(saved_path)

        existing = self._repository.get_by_sha256(sha256)

        if existing:
            LOGGER.info("Evidence upload matched existing SHA-256 %s", sha256)
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

        saved = self._repository.create(evidence)
        self._custody.record_event(
            CustodyCreate(
                evidence_id=saved.id,
                action="uploaded",
                performed_by=uploaded_by,
                location=None,
                notes="Evidence uploaded into ForensicX",
            )
        )
        LOGGER.info("Registered evidence %s for case %s", saved.id, case_id)
        return saved

    async def validate_upload(self, upload: UploadFile) -> tuple[str, str, int]:
        """Validate an evidence upload without storing it."""
        size = await self._validator.validate(upload)
        filename = upload.filename or ""
        extension = Path(filename).suffix.lower()
        LOGGER.info("Validated evidence upload %s (%d bytes)", filename, size)
        return filename, extension, size

    def get(self, evidence_id: str) -> Evidence:
        """Return evidence by ID."""
        evidence = self._require_evidence(evidence_id)
        LOGGER.info("Read evidence %s", evidence.id)
        return evidence

    def list_case_evidence(self, case_id: int, *, offset: int, limit: int) -> tuple[list[Evidence], int]:
        """Return a paginated list of evidence belonging to a case."""
        items = list(self._repository.list_by_case(case_id, offset=offset, limit=limit))
        total = self._repository.count_by_case(case_id)
        LOGGER.info("Listed %d evidence items for case %s", len(items), case_id)
        return items, total

    def download(self, evidence_id: str) -> Evidence:
        """Return downloadable evidence after verifying the stored file exists."""
        evidence = self._require_evidence(evidence_id)
        if not Path(evidence.storage_path).is_file():
            LOGGER.error("Evidence file is missing for record %s", evidence.id)
            raise ForensicXError("Evidence file is unavailable", 404)
        LOGGER.info("Prepared evidence %s for download", evidence.id)
        self._custody.record_event(
            CustodyCreate(
                evidence_id=evidence.id,
                action="downloaded",
                performed_by=evidence.uploaded_by,
                location=None,
                notes="Evidence downloaded",
            )
        )
        return evidence

    def delete(self, evidence_id: str, performed_by: str | None = None) -> Evidence:
        """Soft-delete evidence while retaining its database row and stored file."""
        evidence = self._require_evidence(evidence_id)
        actor = performed_by or evidence.uploaded_by
        self._custody.record_event(
            CustodyCreate(
                evidence_id=evidence.id,
                action="archived",
                performed_by=actor,
                location=None,
                notes="Evidence registration soft-deleted; stored file retained",
            )
        )
        archived = self._repository.archive(evidence)
        LOGGER.info("Soft-deleted evidence record %s; storage file retained", archived.id)
        return archived

    def _require_evidence(self, evidence_id: str) -> Evidence:
        """Return evidence or raise a consistent not-found error."""
        evidence = self._repository.get_by_id(evidence_id)
        if evidence is None:
            LOGGER.warning("Evidence %s was not found", evidence_id)
            raise ForensicXError("Evidence not found", 404)
        return evidence
