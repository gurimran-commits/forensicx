"""Persistence adapter for case management."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session

from forensicx.modules.cases.models import CaseModel
from forensicx.modules.cases.schemas import CaseSort, CaseStatus


LOGGER = logging.getLogger(__name__)


class CaseRepository:
    """Repository for case management database operations."""

    def __init__(self, session: Session) -> None:
        """Create a repository with a SQLAlchemy session."""
        self._session = session

    def next_case_number(self) -> str:
        """Generate the next monotonic case number for the current year."""
        year = datetime.now(UTC).year
        prefix = f"CASE-{year}-"
        count = self._session.scalar(select(func.count()).select_from(CaseModel).where(CaseModel.case_number.like(f"{prefix}%"))) or 0
        return f"{prefix}{count + 1:04d}"

    def add(self, case: CaseModel) -> CaseModel:
        """Persist a new case and return it with generated fields."""
        self._session.add(case)
        self._session.flush()
        LOGGER.info("Created case %s", case.case_number)
        return case

    def rollback(self) -> None:
        """Reset the session after a failed insert so it can be retried."""
        self._session.rollback()

    def get_by_number(self, case_number: str) -> CaseModel | None:
        """Return a case by its public case number."""
        return self._session.scalar(select(CaseModel).where(CaseModel.case_number == case_number))

    def list(
        self,
        *,
        status: CaseStatus | None,
        search: str | None,
        sort: CaseSort,
        limit: int,
        offset: int,
    ) -> tuple[list[CaseModel], int]:
        """Return filtered, sorted, paginated cases and total count."""
        statement = self._filtered_statement(status=status, search=search)
        total = self._session.scalar(select(func.count()).select_from(statement.subquery())) or 0
        order_column = getattr(CaseModel, sort)
        rows = self._session.scalars(statement.order_by(order_column.desc()).limit(limit).offset(offset)).all()
        return list(rows), total

    def update_status(self, case: CaseModel, status: CaseStatus) -> CaseModel:
        """Update a case status."""
        case.status = status
        case.updated_at = datetime.now(UTC)
        self._session.flush()
        LOGGER.info("Updated case %s status to %s", case.case_number, status)
        return case

    def _filtered_statement(self, *, status: CaseStatus | None, search: str | None) -> Select[tuple[CaseModel]]:
        """Build a filtered case query."""
        statement = select(CaseModel)
        if status:
            statement = statement.where(CaseModel.status == status)
        if search:
            like = f"%{search.strip()}%"
            statement = statement.where(
                or_(
                    CaseModel.case_number.ilike(like),
                    CaseModel.title.ilike(like),
                    CaseModel.description.ilike(like),
                    CaseModel.lead_investigator.ilike(like),
                )
            )
        return statement
