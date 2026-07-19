"""OpenAPI schemas for the forensic analysis engine."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from forensicx.modules.forensic_engine.domain import AnalysisStatus


class ForensicAnalysisRead(BaseModel):
    """One persisted analyzer result."""
    model_config = ConfigDict(from_attributes=True)
    id: int
    evidence_id: str
    analyzer_name: str
    analyzer_version: str
    status: AnalysisStatus
    findings: dict[str, Any]
    error_message: str | None
    analyzed_by: str
    created_at: datetime


class ForensicAnalysisRunResponse(BaseModel):
    """Results produced by a single analysis request."""
    evidence_id: str
    results: list[ForensicAnalysisRead]


class ForensicAnalysisListResponse(BaseModel):
    """Paginated historical results for immutable evidence."""
    items: list[ForensicAnalysisRead]
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
