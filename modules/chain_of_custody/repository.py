"""
Repository for Chain of Custody persistence.
"""

from __future__ import annotations

import logging

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from forensicx.modules.chain_of_custody.domain import CustodyRecord
from forensicx.modules.chain_of_custody.models import ChainOfCustody

LOGGER = logging.getLogger(__name__)


class ChainOfCustodyRepository:
    """Persistence layer for custody events."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, event: ChainOfCustody) -> ChainOfCustody:
        """Persist a custody event."""

        self._session.add(event)
        self._session.flush()

        LOGGER.info(
            "Created custody event %s for evidence %s",
            event.id,
            event.evidence_id,
        )

        return event

    def get(self, event_id: int) -> ChainOfCustody | None:
        """Return a custody event by ID."""

        statement = select(ChainOfCustody).where(
            ChainOfCustody.id == event_id
        )

        return self._session.scalar(statement)

    def list_by_evidence(
        self,
        evidence_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[CustodyRecord], int]:
        """Return custody history for an evidence item."""

        total = self._session.scalar(
            select(func.count()).select_from(ChainOfCustody).where(
                ChainOfCustody.evidence_id == evidence_id
            )
        ) or 0

        statement = (
            select(ChainOfCustody)
            .where(ChainOfCustody.evidence_id == evidence_id)
            .order_by(ChainOfCustody.performed_at.desc())
            .offset(offset)
            .limit(limit)
        )

        events = self._session.scalars(statement).all()

        return (
            [self._to_domain(event) for event in events],
            total,
        )

    def delete(self, event: ChainOfCustody) -> None:
        """Delete a custody event."""

        self._session.delete(event)
        self._session.flush()

    @staticmethod
    def _to_domain(event: ChainOfCustody) -> CustodyRecord:
        """Convert ORM model into domain object."""

        return CustodyRecord(
            id=event.id,
            evidence_id=event.evidence_id,
            action=event.action.value,
            performed_by=event.performed_by,
            location=event.location,
            notes=event.notes,
            performed_at=event.performed_at,
        )
