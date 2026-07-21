"""Persistence adapter for extracted indicators."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from forensicx.modules.ioc.models import Ioc


class IocRepository:
    """Store and retrieve normalized IOC records."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add_new(self, evidence_id: str, extracted: dict[str, set[str]]) -> list[Ioc]:
        """Store values not already recorded for the evidence item."""
        existing = {
            (indicator.indicator_type, indicator.value)
            for indicator in self._session.scalars(select(Ioc).where(Ioc.evidence_id == evidence_id))
        }
        records = [
            Ioc(evidence_id=evidence_id, indicator_type=indicator_type, value=value)
            for indicator_type, values in extracted.items()
            for value in sorted(values)
            if (indicator_type, value) not in existing
        ]
        self._session.add_all(records)
        self._session.flush()
        return records

    def list_for_evidence(self, evidence_id: str, *, offset: int, limit: int) -> list[Ioc]:
        """Return persisted indicators in stable newest-first order."""
        statement = (
            select(Ioc)
            .where(Ioc.evidence_id == evidence_id)
            .order_by(Ioc.created_at.desc(), Ioc.id.desc())
            .offset(offset)
            .limit(limit)
        )
        return list(self._session.scalars(statement))
