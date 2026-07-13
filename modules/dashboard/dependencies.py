"""Dependency injection helpers for dashboard routes."""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.orm import Session

from forensicx.modules.cases.repository import CaseRepository
from forensicx.modules.dashboard.repository import DashboardRepository
from forensicx.modules.dashboard.service import DashboardService
from forensicx.modules.evidence.repository import EvidenceRepository
from forensicx.platform.dependencies import database_session


def dashboard_service(session: Session = Depends(database_session)) -> DashboardService:
    """Build a dashboard service for the current request."""
    repository = DashboardRepository(CaseRepository(session), EvidenceRepository(session))
    return DashboardService(repository)
