"""
Repository layer for Threat Intelligence persistence.
"""

from __future__ import annotations

from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from forensicx.modules.threat_intelligence.models import (
    ThreatIntel,
    ThreatSource,
)


class ThreatIntelRepository:
    """Repository responsible for Threat Intelligence persistence."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, intel: ThreatIntel) -> ThreatIntel:
        """Persist a threat intelligence record."""
        self._session.add(intel)
        self._session.flush()
        return intel

    def get_by_id(self, intel_id: int) -> ThreatIntel | None:
        """Return one threat intelligence record."""
        statement = (
            select(ThreatIntel)
            .where(ThreatIntel.id == intel_id)
        )

        return self._session.scalar(statement)

    def list_by_ioc(
        self,
        ioc_id: int,
        offset: int = 0,
        limit: int = 100,
    ) -> Sequence[ThreatIntel]:
        """Return enrichment results for one IOC."""
        statement = (
            select(ThreatIntel)
            .where(ThreatIntel.ioc_id == ioc_id)
            .order_by(ThreatIntel.created_at.desc())
            .offset(offset)
            .limit(limit)
        )

        return self._session.scalars(statement).all()

    def update(self, intel: ThreatIntel) -> ThreatIntel:
        """Flush changes."""
        self._session.add(intel)
        self._session.flush()
        return intel

    def delete(self, intel: ThreatIntel) -> None:
        """Delete one record."""
        self._session.delete(intel)
        self._session.flush()

    def count_all(self) -> int:
        """Return total intelligence records."""
        statement = (
            select(func.count())
            .select_from(ThreatIntel)
        )

        return int(self._session.scalar(statement) or 0)

    def exists(
        self,
        ioc_id: int,
        source: ThreatSource,
    ) -> bool:
        """Return True if enrichment already exists."""
        statement = (
            select(func.count())
            .select_from(ThreatIntel)
            .where(ThreatIntel.ioc_id == ioc_id)
            .where(ThreatIntel.source == source)
        )

        return bool(self._session.scalar(statement))
