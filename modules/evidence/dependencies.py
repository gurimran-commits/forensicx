"""
Dependency providers for the Evidence module.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.orm import Session

from forensicx.platform.config import get_settings
from forensicx.platform.database import get_db

from forensicx.modules.evidence.service import EvidenceService


def evidence_service(
    session: Session = Depends(get_db),
) -> EvidenceService:
    """Provide an EvidenceService instance."""

    settings = get_settings()

    return EvidenceService(
        session=session,
        storage_root=settings.storage_path,
    )
