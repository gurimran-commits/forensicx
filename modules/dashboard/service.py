"""Application service for dashboard use cases."""

from __future__ import annotations

import logging

from forensicx.modules.dashboard.repository import DashboardRepository
from forensicx.modules.dashboard.schemas import DashboardOverview


LOGGER = logging.getLogger(__name__)


class DashboardService:
    """Dashboard application service."""

    def __init__(self, repository: DashboardRepository) -> None:
        """Create the service with its persistence dependency."""
        self._repository = repository

    def overview(self) -> DashboardOverview:
        """Return the latest validated dashboard overview."""
        snapshot = self._repository.get_snapshot()
        payload = dict(snapshot.payload)
        payload["generated_at"] = snapshot.generated_at
        overview = DashboardOverview.model_validate(payload)
        LOGGER.info("Dashboard overview loaded with %d KPI cards", len(overview.kpis))
        return overview
