"""Dependency injection helpers for evidence management routes."""

from __future__ import annotations

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from forensicx.modules.chain_of_custody.dependencies import custody_service
from forensicx.modules.chain_of_custody.service import ChainOfCustodyService

from forensicx.modules.evidence.repository import EvidenceRepository
from forensicx.modules.evidence.service import EvidenceService
from forensicx.modules.evidence.services.hashing import HashingService
from forensicx.modules.evidence.services.metadata import MetadataService
from forensicx.modules.evidence.services.storage import StorageService
from forensicx.modules.evidence.services.validator import EvidenceValidator
from forensicx.platform.dependencies import database_session


def evidence_service(
    request: Request,
    session: Session = Depends(database_session),
    custody: ChainOfCustodyService = Depends(custody_service),
) -> EvidenceService:
    """Build an evidence service for the current request."""
    return EvidenceService(
        repository=EvidenceRepository(session),
        storage=StorageService(request.app.state.settings.storage_path),
        hashing=HashingService(),
        metadata=MetadataService(),
        custody_service=custody,
        validator=EvidenceValidator(
            request.app.state.settings.max_upload_size,
            request.app.state.settings.allowed_extensions,
        ),
    )
