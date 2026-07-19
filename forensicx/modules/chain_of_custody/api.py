"""
Chain of Custody REST API routes.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query

from forensicx.modules.chain_of_custody.dependencies import custody_service
from forensicx.modules.chain_of_custody.schemas import (
    CustodyListResponse,
    CustodyRead,
)
from forensicx.modules.chain_of_custody.service import (
    ChainOfCustodyService,
)
from forensicx.platform.security import (
    Principal,
    require_role,
)

router = APIRouter(
    prefix="/chain-of-custody",
    tags=["chain-of-custody"],
)


@router.get(
    "/evidence/{evidence_id}",
    response_model=CustodyListResponse,
    summary="Read custody history",
    description="Returns the complete custody timeline for one evidence item.",
)
async def list_custody_events(
    evidence_id: UUID,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(require_role("evidence:read")),
    service: ChainOfCustodyService = Depends(custody_service),
) -> CustodyListResponse:
    """Return custody history for one evidence item."""

    _ = principal

    return service.list_events(
        evidence_id=str(evidence_id),
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{event_id}",
    response_model=CustodyRead,
    summary="Read custody event",
    description="Returns one custody event.",
)
async def get_custody_event(
    event_id: int,
    principal: Principal = Depends(require_role("evidence:read")),
    service: ChainOfCustodyService = Depends(custody_service),
) -> CustodyRead:
    """Return one custody event."""

    _ = principal

    return service.get_event(event_id)
