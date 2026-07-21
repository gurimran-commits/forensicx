"""Tests for collision-safe case-number allocation."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.exc import IntegrityError

from forensicx.modules.cases.models import CaseModel
from forensicx.modules.cases.schemas import CaseCreate
from forensicx.modules.cases.service import CaseService
from forensicx.platform import model_registry as _model_registry


class _CollisionRepository:
    """Repository double that simulates a concurrent insert winning once."""

    def __init__(self) -> None:
        self.numbers = iter(["CASE-2026-0001", "CASE-2026-0002"])
        self.add_attempts = 0
        self.rollbacks = 0

    def next_case_number(self) -> str:
        return next(self.numbers)

    def add(self, case: CaseModel) -> CaseModel:
        self.add_attempts += 1
        if self.add_attempts == 1:
            raise IntegrityError("INSERT INTO cases", {}, Exception("UNIQUE constraint failed: cases.case_number"))
        case.id = 1
        case.created_at = datetime.now(UTC)
        case.updated_at = datetime.now(UTC)
        return case

    def rollback(self) -> None:
        self.rollbacks += 1


def test_create_case_retries_after_a_case_number_collision() -> None:
    """A unique-constraint collision is retried with a newly allocated number."""
    repository = _CollisionRepository()
    service = CaseService(repository)  # type: ignore[arg-type]

    created = service.create_case(
        CaseCreate(title="Collision test", description="Verifies case-number collision retries.", priority="Medium", lead_investigator="Analyst")
    )

    assert created.case_number == "CASE-2026-0002"
    assert repository.add_attempts == 2
    assert repository.rollbacks == 1
