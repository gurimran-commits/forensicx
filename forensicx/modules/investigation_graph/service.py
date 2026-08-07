"""
Service for Investigation Graphs.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from forensicx.modules.cases.repository import CaseRepository
from forensicx.modules.correlation.repository import CorrelationRepository
from forensicx.modules.evidence.repository import EvidenceRepository
from forensicx.modules.investigation_graph.graph_builder import (
    InvestigationGraphBuilder,
)
from forensicx.modules.ioc.repository import IocRepository
from forensicx.modules.threat_intelligence.repository import (
    ThreatIntelRepository,
)


class InvestigationGraphService:
    """Service responsible for investigation graph generation."""

    def __init__(self, session: Session):

        self._builder = InvestigationGraphBuilder(
            CaseRepository(session),
            EvidenceRepository(session),
            IocRepository(session),
            CorrelationRepository(session),
            ThreatIntelRepository(session),
        )

    def build_case_graph(
        self,
        case_id: int,
    ) -> dict:

        return self._builder.build_case_graph(case_id)
