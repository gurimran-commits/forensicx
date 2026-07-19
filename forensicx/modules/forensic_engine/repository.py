"""Persistence adapter for forensic analysis results."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from forensicx.modules.forensic_engine.models import ForensicAnalysisResult


class ForensicAnalysisRepository:
    """Persist results using flush only; request scope owns commit/rollback."""
    def __init__(self, session: Session) -> None:
        self._session = session

    def add_all(self, results: list[ForensicAnalysisResult]) -> list[ForensicAnalysisResult]:
        """Stage results in the active transaction."""
        self._session.add_all(results)
        self._session.flush()
        return results

    def list_for_evidence(self, evidence_id: str, *, offset: int, limit: int) -> list[ForensicAnalysisResult]:
        """Return newest persisted analysis results for one evidence item."""
        statement = select(ForensicAnalysisResult).where(ForensicAnalysisResult.evidence_id == evidence_id).order_by(ForensicAnalysisResult.created_at.desc(), ForensicAnalysisResult.id.desc()).offset(offset).limit(limit)
        return list(self._session.scalars(statement))
