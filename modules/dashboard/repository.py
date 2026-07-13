"""Data access composition for the live dashboard."""

from __future__ import annotations

from forensicx.modules.cases.models import CaseModel
from forensicx.modules.cases.repository import CaseRepository
from forensicx.modules.evidence.models import EvidenceStatus
from forensicx.modules.evidence.repository import EvidenceRepository


class DashboardRepository:
    """Loads dashboard source data through the Cases and Evidence repositories."""

    def __init__(self, cases: CaseRepository, evidence: EvidenceRepository) -> None:
        """Create a dashboard data adapter from existing module repositories."""
        self._cases = cases
        self._evidence = evidence

    def total_cases(self) -> int:
        """Return the total number of cases."""
        _, total = self._cases.list(status=None, search=None, sort="created_at", limit=1, offset=0)
        return total

    def active_cases(self) -> int:
        """Return all cases that have not reached the closed lifecycle state."""
        total = self.total_cases()
        _, closed = self._cases.list(status="closed", search=None, sort="created_at", limit=1, offset=0)
        return total - closed

    def recent_cases(self, limit: int = 5) -> list[CaseModel]:
        """Return the most recently created cases."""
        cases, _ = self._cases.list(status=None, search=None, sort="created_at", limit=limit, offset=0)
        return cases

    def total_evidence(self) -> int:
        """Return the total number of registered evidence items."""
        return self._evidence.count_all()

    def analyzed_evidence(self) -> int:
        """Return the number of evidence items whose analysis has completed."""
        return self._evidence.count_by_status(EvidenceStatus.ANALYZED)

    def evidence_categories(self) -> list[tuple[str, int]]:
        """Return live evidence counts grouped by file extension."""
        return self._evidence.count_by_extension()
