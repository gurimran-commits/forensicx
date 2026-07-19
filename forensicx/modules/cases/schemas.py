"""Pydantic DTOs for case management APIs."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


CasePriority = Literal["Low", "Medium", "High", "Critical"]
CaseStatus = Literal["open", "triaged", "investigating", "contained", "closed"]
CaseSort = Literal["created_at", "updated_at", "priority", "status", "case_number"]


class CaseCreate(BaseModel):
    """Request DTO for creating a DFIR case."""

    title: str = Field(min_length=3, max_length=180, description="Human-readable case title")
    description: str = Field(min_length=10, max_length=4000, description="Initial investigation summary")
    priority: CasePriority = Field(default="Medium", description="Initial case priority")
    lead_investigator: str = Field(min_length=2, max_length=120, description="Assigned lead investigator")


class CaseStatusUpdate(BaseModel):
    """Request DTO for updating case status."""

    status: CaseStatus = Field(description="New lifecycle status")


class CaseRead(BaseModel):
    """Response DTO for a DFIR case."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    case_number: str
    title: str
    description: str
    priority: CasePriority
    status: CaseStatus
    lead_investigator: str
    created_at: datetime
    updated_at: datetime


class CaseListResponse(BaseModel):
    """Paginated case list response."""

    items: list[CaseRead]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
