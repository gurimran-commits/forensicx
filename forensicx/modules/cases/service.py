"""Application service for case management."""

from __future__ import annotations

import logging

from sqlalchemy.exc import IntegrityError

from forensicx.modules.cases.models import CaseModel
from forensicx.modules.cases.repository import CaseRepository
from forensicx.modules.cases.schemas import CaseCreate, CaseListResponse, CaseRead, CaseSort, CaseStatus
from forensicx.platform.errors import ForensicXError


LOGGER = logging.getLogger(__name__)


class CaseService:
    """Case management use cases."""

    _CREATE_RETRY_LIMIT = 3

    def __init__(self, repository: CaseRepository) -> None:
        """Create a service with its repository dependency."""
        self._repository = repository

    def create_case(self, request: CaseCreate) -> CaseRead:
        """Create a case, retrying if a concurrent insert claims its number."""
        last_error: IntegrityError | None = None
        for attempt in range(1, self._CREATE_RETRY_LIMIT + 1):
            case = CaseModel(
                case_number=self._repository.next_case_number(),
                title=request.title,
                description=request.description,
                priority=request.priority,
                status="open",
                lead_investigator=request.lead_investigator,
            )
            try:
                saved = self._repository.add(case)
            except IntegrityError as exc:
                last_error = exc
                self._repository.rollback()
                LOGGER.warning(
                    "Case-number collision for %s (attempt %d of %d)",
                    case.case_number,
                    attempt,
                    self._CREATE_RETRY_LIMIT,
                )
                continue
            LOGGER.info("Case service created %s", saved.case_number)
            return CaseRead.model_validate(saved)
        raise ForensicXError("Unable to allocate a unique case number; please retry", 409) from last_error

    def get_case(self, case_number: str) -> CaseRead:
        """Return one case by public case number."""
        case = self._repository.get_by_number(case_number)
        if case is None:
            raise ForensicXError("Case not found", 404)
        return CaseRead.model_validate(case)

    def list_cases(
        self,
        *,
        status: CaseStatus | None,
        search: str | None,
        sort: CaseSort,
        limit: int,
        offset: int,
    ) -> CaseListResponse:
        """Return a paginated list of cases."""
        items, total = self._repository.list(status=status, search=search, sort=sort, limit=limit, offset=offset)
        return CaseListResponse(
            items=[CaseRead.model_validate(item) for item in items],
            total=total,
            limit=limit,
            offset=offset,
        )

    def update_status(self, case_number: str, status: CaseStatus) -> CaseRead:
        """Update and return a case status."""
        case = self._repository.get_by_number(case_number)
        if case is None:
            raise ForensicXError("Case not found", 404)
        return CaseRead.model_validate(self._repository.update_status(case, status))
