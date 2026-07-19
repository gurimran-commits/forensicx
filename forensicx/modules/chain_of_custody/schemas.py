"""
Pydantic DTOs for Chain of Custody APIs.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


CustodyAction = Literal[
    "uploaded",
    "downloaded",
    "verified",
    "analyzed",
    "archived",
    "deleted",
    "exported",
    "updated",
]


class CustodyCreate(BaseModel):
    """Request DTO for creating a custody event."""

    evidence_id: str = Field(
        min_length=36,
        max_length=36,
        description="Evidence UUID",
    )

    action: CustodyAction = Field(
        description="Custody action performed",
    )

    performed_by: str = Field(
        min_length=2,
        max_length=120,
        description="User performing the action",
    )

    location: str | None = Field(
        default=None,
        max_length=255,
        description="Physical or logical location",
    )

    notes: str | None = Field(
        default=None,
        max_length=2000,
        description="Optional custody notes",
    )


class CustodyRead(BaseModel):
    """Response DTO for a custody event."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    evidence_id: str
    action: CustodyAction
    performed_by: str
    location: str | None
    notes: str | None
    performed_at: datetime


class CustodyListResponse(BaseModel):
    """Paginated custody history."""

    items: list[CustodyRead]

    total: int = Field(ge=0)

    limit: int = Field(
        ge=1,
        le=100,
    )

    offset: int = Field(
        ge=0,
    )
