"""
Domain objects for chain of custody.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class CustodyRecord:
    """Immutable chain of custody event."""

    id: int
    evidence_id: str
    action: str
    performed_by: str
    location: str | None
    notes: str | None
    performed_at: datetime
