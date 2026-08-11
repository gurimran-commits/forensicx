"""Dependency injection for forensic analysis routes."""

from __future__ import annotations

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from forensicx.modules.correlation.service import CorrelationService
from forensicx.modules.evidence.repository import EvidenceRepository
from forensicx.modules.forensic_engine.registry import AnalyzerRegistry
from forensicx.modules.forensic_engine.repository import ForensicAnalysisRepository
from forensicx.modules.forensic_engine.service import ForensicAnalysisService
from forensicx.modules.ioc.repository import IocRepository
from forensicx.modules.ioc.service import IocExtractionService
from forensicx.platform.dependencies import database_session

from forensicx.modules.threat_intelligence.service import ThreatIntelService

def forensic_analysis_service(
    request: Request,
    session: Session = Depends(database_session),
) -> ForensicAnalysisService:
    """Create a request-scoped forensic analysis service."""

    evidence_repository = EvidenceRepository(session)
    analysis_repository = ForensicAnalysisRepository(session)

    ioc_service = IocExtractionService(
        evidence_repository,
        IocRepository(session),
        CorrelationService(session),
        ThreatIntelService(session),
        request.app.state.settings.storage_path,
    )

    return ForensicAnalysisService(
        evidence_repository,
        analysis_repository,
        AnalyzerRegistry(),
        request.app.state.settings.storage_path,
        ioc_service,
    )
