from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from forensicx.modules.correlation.models import Correlation


class CorrelationRepository:
    def __init__(self, session: Session):
        self._session = session

    def create(self, correlation: Correlation) -> Correlation:
        self._session.add(correlation)
        self._session.commit()
        self._session.refresh(correlation)
        return correlation

    def get(self, correlation_id: int) -> Correlation | None:
        return self._session.get(Correlation, correlation_id)

    def list_by_case(self, case_id: int) -> list[Correlation]:
        stmt = (
            select(Correlation)
            .where(Correlation.case_id == case_id)
            .order_by(Correlation.created_at.desc())
        )
        return list(self._session.scalars(stmt))

    def list_by_source(
        self,
        source_type: str,
        source_id: int,
    ) -> list[Correlation]:
        stmt = (
            select(Correlation)
            .where(
                Correlation.source_type == source_type,
                Correlation.source_id == source_id,
            )
        )
        return list(self._session.scalars(stmt))

    def delete(self, correlation: Correlation) -> None:
        self._session.delete(correlation)
        self._session.commit()

    def count(self) -> int:
        return self._session.query(Correlation).count()
