"""
Repository layer for correlation persistence.
"""

from __future__ import annotations

from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from forensicx.modules.correlation.models import (
    Correlation,
    EntityType,
)


class CorrelationRepository:
    """Repository responsible for Correlation persistence."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, correlation: Correlation) -> Correlation:
        """Persist a new correlation."""
        self._session.add(correlation)
        self._session.flush()
        return correlation

    def get_by_id(self, correlation_id: int) -> Correlation | None:
        """Return a correlation by ID."""
        statement = (
            select(Correlation)
            .where(Correlation.id == correlation_id)
        )
        return self._session.scalar(statement)

    def list_by_case(
        self,
        case_id: int,
        offset: int = 0,
        limit: int = 100,
    ) -> Sequence[Correlation]:
        """Return correlations belonging to a case."""
        statement = (
            select(Correlation)
            .where(Correlation.case_id == case_id)
            .offset(offset)
            .limit(limit)
            .order_by(Correlation.created_at.desc())
        )

        return self._session.scalars(statement).all()

    def list_by_source(
        self,
        source_type: EntityType,
        source_id: int,
    ) -> Sequence[Correlation]:
        """Return correlations originating from an entity."""
        statement = (
            select(Correlation)
            .where(Correlation.source_type == source_type)
            .where(Correlation.source_id == source_id)
            .order_by(Correlation.created_at.desc())
        )

        return self._session.scalars(statement).all()

    def update(self, correlation: Correlation) -> Correlation:
        """Flush correlation changes."""
        self._session.add(correlation)
        self._session.flush()
        return correlation

    def delete(self, correlation: Correlation) -> None:
        """Delete a correlation."""
        self._session.delete(correlation)
        self._session.flush()

    def exists(self, correlation_id: int) -> bool:
        """Check whether a correlation exists."""
        statement = (
            select(func.count())
            .select_from(Correlation)
            .where(Correlation.id == correlation_id)
        )

        return bool(self._session.scalar(statement))

    def count_by_case(self, case_id: int) -> int:
        """Return number of correlations for a case."""
        statement = (
            select(func.count())
            .select_from(Correlation)
            .where(Correlation.case_id == case_id)
        )

        return int(self._session.scalar(statement) or 0)

    def count_all(self) -> int:
        """Return total number of correlations."""
        statement = (
            select(func.count())
            .select_from(Correlation)
        )

        return int(self._session.scalar(statement) or 0)
