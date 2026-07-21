"""API schemas for IOC extraction."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class IocRead(BaseModel):
    """One stored indicator."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    evidence_id: str
    indicator_type: str
    value: str
    created_at: datetime


class IocExtractionResponse(BaseModel):
    """Indicators stored by one extraction request."""

    evidence_id: str
    items: list[IocRead]


class IocListResponse(BaseModel):
    """Paginated indicators for one evidence item."""

    items: list[IocRead]
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
