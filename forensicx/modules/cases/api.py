"""Case management REST API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Path, Query, status

from forensicx.modules.cases.dependencies import case_service
from forensicx.modules.cases.schemas import CaseCreate, CaseListResponse, CaseRead, CaseSort, CaseStatus, CaseStatusUpdate
from forensicx.modules.cases.service import CaseService
from forensicx.platform.security import Principal, require_role


router = APIRouter(prefix="/cases", tags=["cases"])


@router.post(
    "",
    response_model=CaseRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a DFIR case",
    description="Creates a new investigation case with validation, authentication, RBAC, logging, and ORM persistence.",
)
async def create_case(
    payload: CaseCreate,
    principal: Principal = Depends(require_role("cases:write")),
    service: CaseService = Depends(case_service),
) -> CaseRead:
    """Create a new case."""
    _ = principal
    return service.create_case(payload)


@router.get(
    "",
    response_model=CaseListResponse,
    summary="List DFIR cases",
    description="Returns cases with pagination, status filtering, search, and sorting.",
)
async def list_cases(
    status_filter: CaseStatus | None = Query(default=None, alias="status", description="Filter by case lifecycle status."),
    search: str | None = Query(default=None, min_length=2, max_length=100, description="Search title, number, investigator, or description."),
    sort: CaseSort = Query(default="created_at", description="Sort field."),
    limit: int = Query(default=25, ge=1, le=100, description="Maximum cases returned."),
    offset: int = Query(default=0, ge=0, description="Pagination offset."),
    principal: Principal = Depends(require_role("cases:read")),
    service: CaseService = Depends(case_service),
) -> CaseListResponse:
    """List cases."""
    _ = principal
    return service.list_cases(status=status_filter, search=search, sort=sort, limit=limit, offset=offset)


@router.get(
    "/{case_number}",
    response_model=CaseRead,
    summary="Read a DFIR case",
    description="Returns one case by public case number.",
)
async def get_case(
    case_number: str = Path(min_length=10, max_length=32, description="Public case number, for example CASE-2026-0001."),
    principal: Principal = Depends(require_role("cases:read")),
    service: CaseService = Depends(case_service),
) -> CaseRead:
    """Read one case."""
    _ = principal
    return service.get_case(case_number)


@router.patch(
    "/{case_number}/status",
    response_model=CaseRead,
    summary="Update case status",
    description="Updates the lifecycle status for an existing investigation case.",
)
async def update_case_status(
    payload: CaseStatusUpdate,
    case_number: str = Path(min_length=10, max_length=32, description="Public case number, for example CASE-2026-0001."),
    principal: Principal = Depends(require_role("cases:write")),
    service: CaseService = Depends(case_service),
) -> CaseRead:
    """Update case status."""
    _ = principal
    return service.update_status(case_number, payload.status)
