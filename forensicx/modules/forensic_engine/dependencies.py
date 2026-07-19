"""Dependency injection for forensic analysis routes."""
from __future__ import annotations

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from forensicx.modules.evidence.repository import EvidenceRepository
from forensicx.modules.forensic_engine.registry import AnalyzerRegistry
from forensicx.modules.forensic_engine.repository import ForensicAnalysisRepository
from forensicx.modules.forensic_engine.service import ForensicAnalysisService
from forensicx.platform.dependencies import database_session


def forensic_analysis_service(request: Request, session: Session = Depends(database_session)) -> ForensicAnalysisService:
    """Create a request-scoped forensic analysis service."""
    return ForensicAnalysisService(EvidenceRepository(session), ForensicAnalysisRepository(session), AnalyzerRegistry(), request.app.state.settings.storage_path)
