"""Persistence adapter for extracted indicators."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from forensicx.modules.ioc.models import Ioc

from forensicx.modules.evidence.models import Evidence


class IocRepository:
    """Store and retrieve normalized IOC records."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add_new(self, evidence_id: str, extracted: dict[str, set[str]]) -> list[Ioc]:
        """Store values not already recorded for the evidence item."""
        existing = {
            (indicator.indicator_type, indicator.value)
            for indicator in self._session.scalars(
                select(Ioc).where(Ioc.evidence_id == evidence_id)
            )
        }

        records = [
            Ioc(
                evidence_id=evidence_id,
                indicator_type=indicator_type,
                value=value,
            )
            for indicator_type, values in extracted.items()
            for value in sorted(values)
            if (indicator_type, value) not in existing
        ]

        self._session.add_all(records)
        self._session.flush()
        return records

    def list_for_evidence(
        self,
        evidence_id: str,
        *,
        offset: int,
        limit: int,
    ) -> list[Ioc]:
        """Return persisted indicators in stable newest-first order."""
        statement = (
            select(Ioc)
            .where(Ioc.evidence_id == evidence_id)
            .order_by(Ioc.created_at.desc(), Ioc.id.desc())
            .offset(offset)
            .limit(limit)
        )

        return list(self._session.scalars(statement))
    
    def get_by_id(
        self,
        ioc_id: int,
    ) -> Ioc | None:
        """Return one IOC by its identifier."""
        statement = (
            select(Ioc)
            .where(Ioc.id == ioc_id)
        )

        return self._session.scalar(statement)
    
    def find_matching(
        self,
        indicator_type: str,
        value: str,
    ) -> list[Ioc]:
        """Return every IOC with the same type and value."""
        statement = (
            select(Ioc)
            .where(Ioc.indicator_type == indicator_type)
            .where(Ioc.value == value)
            .order_by(Ioc.created_at.asc())
        )

        return list(self._session.scalars(statement))

    def find_matching_with_case(
        self,
        indicator_type: str,
        value: str,
    ) -> list[tuple[Ioc, int]]:
        """
        Return matching IOCs together with the case ID
        they belong to.
        """
        statement = (
            select(Ioc, Evidence.case_id)
            .join(Evidence, Ioc.evidence_id == Evidence.id)
            .where(Ioc.indicator_type == indicator_type)
            .where(Ioc.value == value)
            .order_by(Ioc.created_at.asc())
        )

        return [
            (ioc, case_id)
            for ioc, case_id in self._session.execute(statement).all()
        ]
    
    def exists(
        self,
        evidence_id: str,
        indicator_type: str,
        value: str,
    ) -> bool:
        """Return True if an IOC already exists for an evidence item."""
        statement = (
            select(Ioc)
            .where(Ioc.evidence_id == evidence_id)
            .where(Ioc.indicator_type == indicator_type)
            .where(Ioc.value == value)
        )

        return self._session.scalar(statement) is not None
