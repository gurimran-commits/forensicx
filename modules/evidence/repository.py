"""
Repository layer for evidence persistence.
"""

from __future__ import annotations

from typing import Sequence

from sqlalchemy import select, func
from sqlalchemy.orm import Session

from forensicx.modules.evidence.models import Evidence, EvidenceStatus


class EvidenceRepository:
    """Repository responsible for Evidence persistence."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, evidence: Evidence) -> Evidence:
        """Persist a new evidence record."""
        self._session.add(evidence)
        self._session.flush()
        return evidence

    def get_by_id(self, evidence_id: str) -> Evidence | None:
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
        case_id: int,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[Evidence]:
        """Return evidence belonging to a case."""
        statement = (
            select(Evidence)
            .where(Evidence.case_id == case_id)
            .offset(offset)
            .limit(limit)
            .order_by(Evidence.created_at.desc())
        )

        return self._session.scalars(statement).all()

    def update(self, evidence: Evidence) -> Evidence:
        """Flush changes to an evidence record."""
        self._session.add(evidence)
        self._session.flush()
        return evidence

    def delete(self, evidence: Evidence) -> None:
        """Delete an evidence record."""
        self._session.delete(evidence)
        self._session.flush()

    def exists(self, evidence_id: str) -> bool:
        """Check whether an evidence record exists."""
        statement = (
            select(func.count())
            .select_from(Evidence)
            .where(Evidence.id == str(evidence_id))
        )

        return bool(self._session.scalar(statement))

    def count_by_case(self, case_id: int) -> int:
        """Return number of evidence files in a case."""
        statement = (
            select(func.count())
            .select_from(Evidence)
            .where(Evidence.case_id == case_id)
        )

        return int(self._session.scalar(statement) or 0)

    def count_all(self) -> int:
        """Return the total number of registered evidence items."""
        statement = select(func.count()).select_from(Evidence)
        return int(self._session.scalar(statement) or 0)

    def count_by_status(self, status: EvidenceStatus) -> int:
        """Return the number of evidence items in one lifecycle status."""
        statement = select(func.count()).select_from(Evidence).where(Evidence.status == status)
        return int(self._session.scalar(statement) or 0)

    def count_by_extension(self) -> list[tuple[str, int]]:
        """Return evidence counts grouped by stored file extension."""
        statement = (
            select(Evidence.file_extension, func.count())
            .group_by(Evidence.file_extension)
            .order_by(func.count().desc(), Evidence.file_extension.asc())
        )
        return [(extension, int(count)) for extension, count in self._session.execute(statement).all()]

    def search(
        self,
        case_id: int,
        query: str,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[Evidence]:
        """Search evidence by filename."""
        statement = (
            select(Evidence)
            .where(Evidence.case_id == case_id)
            .where(Evidence.original_filename.ilike(f"%{query}%"))
            .offset(offset)
            .limit(limit)
            .order_by(Evidence.created_at.desc())
        )

        return self._session.scalars(statement).all()
