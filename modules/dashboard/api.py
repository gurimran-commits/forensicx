"""Dashboard REST API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from forensicx.modules.dashboard.dependencies import dashboard_service
from forensicx.modules.dashboard.schemas import DashboardOverview
from forensicx.modules.dashboard.service import DashboardService
from forensicx.platform.security import Principal, require_role


router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get(
    "/overview",
    response_model=DashboardOverview,
    summary="Read dashboard overview",
    description="Returns KPI, evidence, timeline, IOC, case, map, status, and alert data for the dashboard.",
)
async def read_dashboard_overview(
    date_range: str | None = Query(default=None, description="Optional date-range filter label."),
    search: str | None = Query(default=None, min_length=2, max_length=100, description="Optional dashboard search term."),
    sort: str = Query(default="severity", pattern="^(severity|label|matches)$", description="Sort mode for supported collections."),
    principal: Principal = Depends(require_role("dashboard:read")),
    service: DashboardService = Depends(dashboard_service),
) -> DashboardOverview:
    """Return the authenticated dashboard overview."""
    _ = (search, sort, principal)
    return service.overview(date_range=date_range)
