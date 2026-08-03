"""
Pydantic schemas for Threat Intelligence.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from forensicx.modules.threat_intelligence.models import ThreatSource


class ThreatIntelCreate(BaseModel):
    ioc_id: int
    source: ThreatSource
    verdict: str
    score: int = 0
    details: dict = {}


class ThreatIntelRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ioc_id: int
    source: ThreatSource
    verdict: str
    score: int
    details: dict
    created_at: datetime


class ThreatIntelUpdate(BaseModel):
    verdict: str | None = None
    score: int | None = None
    details: dict | None = None
