"""Application service for live dashboard use cases."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from forensicx.modules.dashboard.repository import DashboardRepository
from forensicx.modules.dashboard.schemas import (
    DashboardOverview,
    EvidenceCategory,
    KpiCard,
    RecentCase,
    TimelineMetric,
)


LOGGER = logging.getLogger(__name__)

_PRIORITY_COLORS = {
    "Critical": "#e64f56",
    "High": "#ffac32",
    "Medium": "#367cff",
    "Low": "#65a34c",
}
_CATEGORY_COLORS = ("#7452ff", "#3e82ff", "#30df78", "#ffac32", "#ff6540", "#c7557b")


class DashboardService:
    """Builds dashboard responses from persisted Cases and Evidence data."""

    def __init__(self, repository: DashboardRepository) -> None:
        """Create the service with its dashboard data dependency."""
        self._repository = repository

    def overview(self, date_range: str | None = None) -> DashboardOverview:
        """Return the current dashboard state derived from persisted module data."""
        total_cases = self._repository.total_cases()
        active_cases = self._repository.active_cases()
        total_evidence = self._repository.total_evidence()
        analyzed_evidence = self._repository.analyzed_evidence()
        recent_cases = [
            RecentCase(
                title=case.title,
                case_number=case.case_number,
                priority=case.priority,
                age=self._age_label(case.created_at),
                color=_PRIORITY_COLORS.get(case.priority, "#367cff"),
            )
            for case in self._repository.recent_cases()
        ]
        overview = DashboardOverview(
            generated_at=datetime.now(UTC).isoformat(),
            date_range=date_range or "All time",
            kpis=[
                KpiCard(
                    key="active_cases",
                    label="Active Cases",
                    value=str(active_cases),
                    delta=f"{total_cases} total",
                    severity="neutral",
                    icon="case",
                    points=[],
                ),
                KpiCard(
                    key="evidence_items",
                    label="Evidence Items",
                    value=str(total_evidence),
                    delta="Current inventory",
                    severity="neutral",
                    icon="database",
                    points=[],
                ),
                KpiCard(
                    key="analyzed_files",
                    label="Analyzed Files",
                    value=str(analyzed_evidence),
                    delta="Current inventory",
                    severity="neutral",
                    icon="file",
                    points=[],
                ),
            ],
            evidence=self._evidence_categories(total_evidence),
            timeline=[],
            timeline_metrics=[
                TimelineMetric(label="Cases", value=total_cases),
                TimelineMetric(label="Evidence Items", value=total_evidence),
                TimelineMetric(label="Analyzed Files", value=analyzed_evidence),
            ],
            ioc_matches=[],
            recent_cases=recent_cases,
            attack_points=[],
            system_statuses=[],
            system_uptime="Not available",
            alerts=[],
        )
        LOGGER.info(
            "Dashboard overview loaded from live data: %d cases and %d evidence items",
            total_cases,
            total_evidence,
        )
        return overview

    def _evidence_categories(self, total_evidence: int) -> list[EvidenceCategory]:
        """Convert live extension aggregates into dashboard evidence categories."""
        if total_evidence == 0:
            return []
        return [
            EvidenceCategory(
                label=extension.lstrip(".").upper() or "No extension",
                count=count,
                percentage=round((count / total_evidence) * 100, 2),
                color=_CATEGORY_COLORS[index % len(_CATEGORY_COLORS)],
            )
            for index, (extension, count) in enumerate(self._repository.evidence_categories())
        ]

    @staticmethod
    def _age_label(created_at: datetime) -> str:
        """Return a compact display age from a persisted case timestamp."""
        timestamp = created_at if created_at.tzinfo else created_at.replace(tzinfo=UTC)
        elapsed_seconds = max(0, int((datetime.now(UTC) - timestamp).total_seconds()))
        if elapsed_seconds < 60:
            return "just now"
        if elapsed_seconds < 3600:
            return f"{elapsed_seconds // 60}m ago"
        if elapsed_seconds < 86400:
            return f"{elapsed_seconds // 3600}h ago"
        return f"{elapsed_seconds // 86400}d ago"
