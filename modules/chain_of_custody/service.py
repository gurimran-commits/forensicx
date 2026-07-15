"""
Application service for Chain of Custody.
"""

from __future__ import annotations

import logging

from forensicx.modules.chain_of_custody.models import (
    ChainOfCustody,
    CustodyAction,
)
from forensicx.modules.chain_of_custody.repository import (
    ChainOfCustodyRepository,
)
from forensicx.modules.chain_of_custody.schemas import (
    CustodyCreate,
    CustodyListResponse,
    CustodyRead,
)
from forensicx.platform.errors import ForensicXError


LOGGER = logging.getLogger(__name__)


class ChainOfCustodyService:
    """Business use cases for Chain of Custody."""

    def __init__(
        self,
        repository: ChainOfCustodyRepository,
    ) -> None:
        self._repository = repository

    def record_event(
        self,
        request: CustodyCreate,
    ) -> CustodyRead:
        """Create a custody event."""

        event = ChainOfCustody(
            evidence_id=request.evidence_id,
            action=CustodyAction(request.action),
            performed_by=request.performed_by,
            location=request.location,
            notes=request.notes,
        )

        saved = self._repository.create(event)

        LOGGER.info(
            "Recorded custody event '%s' for evidence %s",
            saved.action.value,
            saved.evidence_id,
        )

        return CustodyRead.model_validate(saved)

    def get_event(
        self,
        event_id: int,
    ) -> CustodyRead:
        """Return one custody event."""

        event = self._repository.get(event_id)

        if event is None:
            raise ForensicXError(
                "Custody event not found",
                404,
            )

        return CustodyRead.model_validate(event)

    def list_events(
        self,
        evidence_id: str,
        *,
        limit: int,
        offset: int,
    ) -> CustodyListResponse:
        """Return custody history."""

        events, total = self._repository.list_by_evidence(
            evidence_id=evidence_id,
            limit=limit,
            offset=offset,
        )

        return CustodyListResponse(
            items=[
                CustodyRead.model_validate(event)
                for event in events
            ],
            total=total,
            limit=limit,
            offset=offset,
        )
