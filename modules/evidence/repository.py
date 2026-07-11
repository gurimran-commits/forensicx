"""
Repository layer for evidence persistence.
"""

from __future__ import annotations

from typing import Sequence
from uuid import UUID

from sqlalchemy import select, func
from sqlalchemy.orm import Session

from forensicx.modules.evidence.models import Evidence


class EvidenceRepository:
    """Repository responsible for Evidence persistence."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, evidence: Evidence) -> Evidence:
        """Persist a new evidence record."""
        self._session.add(evidence)
        self._session.commit()
        self._session.refresh(evidence)
        return evidence

    def get_by_id(self, evidence_id: UUID) -> Evidence | None:
        """Return an evidence item by ID."""
        statement = (
            select(Evidence)
            .where(Evidence.id == str(evidence_id))
        )

        return self._session.scalar(statement)

    def get_by_sha256(self, sha256: str) -> Evidence | None:
        """Return evidence with matching SHA-256."""
        statement = (
            select(Evidence)
            .where(Evidence.sha256 == sha256)
        )

        return self._session.scalar(statement)

    def list_by_case(
        self,
        case_id: UUID,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[Evidence]:
        """Return evidence belonging to a case."""
        statement = (
            select(Evidence)
            .where(Evidence.case_id == str(case_id))
            .offset(offset)
            .limit(limit)
            .order_by(Evidence.created_at.desc())
        )

        return self._session.scalars(statement).all()

    def update(self, evidence: Evidence) -> Evidence:
        """Commit changes to an evidence record."""
        self._session.add(evidence)
        self._session.commit()
        self._session.refresh(evidence)
        return evidence

    def delete(self, evidence: Evidence) -> None:
        """Delete an evidence record."""
        self._session.delete(evidence)
        self._session.commit()

    def exists(self, evidence_id: UUID) -> bool:
        """Check whether an evidence record exists."""
        statement = (
            select(func.count())
            .select_from(Evidence)
            .where(Evidence.id == str(evidence_id))
        )

        return bool(self._session.scalar(statement))

    def count_by_case(self, case_id: UUID) -> int:
        """Return number of evidence files in a case."""
        statement = (
            select(func.count())
            .select_from(Evidence)
            .where(Evidence.case_id == str(case_id))
        )

        return int(self._session.scalar(statement) or 0)

    def search(
        self,
        case_id: UUID,
        query: str,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[Evidence]:
        """Search evidence by filename."""
        statement = (
            select(Evidence)
            .where(Evidence.case_id == str(case_id))
            .where(Evidence.original_filename.ilike(f"%{query}%"))
            .offset(offset)
            .limit(limit)
            .order_by(Evidence.created_at.desc())
        )

        return self._session.scalars(statement).all()
