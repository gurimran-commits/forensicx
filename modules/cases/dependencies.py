"""Dependency injection helpers for case management routes."""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.orm import Session

from forensicx.modules.cases.repository import CaseRepository
from forensicx.modules.cases.service import CaseService
from forensicx.platform.dependencies import database_session


def case_service(session: Session = Depends(database_session)) -> CaseService:
    """Build a case service for the current request."""
    return CaseService(CaseRepository(session))
