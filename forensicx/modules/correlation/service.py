"""
Service layer for correlation operations.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from forensicx.modules.correlation.models import Correlation
from forensicx.modules.correlation.repository import CorrelationRepository
from forensicx.modules.correlation.schemas import (
    CorrelationCreate,
    CorrelationUpdate,
)

from forensicx.modules.correlation.engine import CorrelationEngine
from forensicx.modules.ioc.repository import IocRepository

class CorrelationService:
    """Business logic for correlation management."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._repository = CorrelationRepository(session)
    
        self._ioc_repository = IocRepository(session)

        self._engine = CorrelationEngine(
            self._ioc_repository,
        )    
    def create(self, data: CorrelationCreate) -> Correlation:
        """Create a new correlation."""

        correlation = Correlation(
            case_id=data.case_id,
            source_type=data.source_type,
            source_id=data.source_id,
            target_type=data.target_type,
            target_id=data.target_id,
            correlation_type=data.correlation_type,
            confidence=data.confidence,
            details=data.details,
        )

        correlation = self._repository.create(correlation)
        self._session.commit()
        self._session.refresh(correlation)

        return correlation

    def get(self, correlation_id: int) -> Correlation | None:
        """Return a correlation by ID."""
        return self._repository.get_by_id(correlation_id)

    def list_by_case(
        self,
        case_id: int,
        offset: int = 0,
        limit: int = 100,
    ):
        """Return correlations belonging to a case."""
        return self._repository.list_by_case(case_id, offset, limit)

    def update(
        self,
        correlation: Correlation,
        data: CorrelationUpdate,
    ) -> Correlation:
        """Update a correlation."""

        if data.confidence is not None:
            correlation.confidence = data.confidence

        if data.details is not None:
            correlation.details = data.details

        correlation = self._repository.update(correlation)

        self._session.commit()
        self._session.refresh(correlation)

        return correlation

    def delete(self, correlation: Correlation) -> None:
        """Delete a correlation."""

        self._repository.delete(correlation)
        self._session.commit()

    def count(self) -> int:
        """Return total correlations."""
        return self._repository.count_all()

    def correlate_evidence(
        self,
        evidence_id: str,
    ) -> int:
        """
        Discover and persist correlations for one evidence item.

        Returns the number of newly created correlations.
        """

        created = 0

        iocs = self._ioc_repository.list_for_evidence(
            evidence_id,
            offset=0,
            limit=10000,
        )

        for ioc in iocs:

            candidates = self._engine.correlate_ioc(ioc)

            for candidate in candidates:

                if self._repository.exists_between(
                    candidate.source_type,
                    candidate.source_id,
                    candidate.target_type,
                    candidate.target_id,
                    candidate.correlation_type,
                ):
                    continue

                correlation = Correlation(
                    case_id=candidate.case_id,
                    source_type=candidate.source_type,
                    source_id=candidate.source_id,
                    target_type=candidate.target_type,
                    target_id=candidate.target_id,
                    correlation_type=candidate.correlation_type,
                    confidence=candidate.confidence,
                    details=candidate.details,
                )

                self._repository.create(correlation)
                created += 1

        if created:
            self._session.commit()

        return created
      
