"""Domain entities for the dashboard module."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DashboardSnapshot:
    """A complete dashboard snapshot for one tenant/time window."""

    generated_at: str
    payload: dict[str, object]
