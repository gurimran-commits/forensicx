"""Domain objects for case management."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class CaseRecord:
    """Case aggregate used by the case management service."""

    id: int
    case_number: str
    title: str
    description: str
    priority: str
    status: str
    lead_investigator: str
    created_at: datetime
    updated_at: datetime
