"""Dependency injection for IOC extraction routes."""

from __future__ import annotations

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from forensicx.modules.evidence.repository import EvidenceRepository
from forensicx.modules.ioc.repository import IocRepository
from forensicx.modules.ioc.service import IocExtractionService
from forensicx.platform.dependencies import database_session


def ioc_extraction_service(request: Request, session: Session = Depends(database_session)) -> IocExtractionService:
    """Build a request-scoped IOC extraction service."""
    return IocExtractionService(EvidenceRepository(session), IocRepository(session), request.app.state.settings.storage_path)
