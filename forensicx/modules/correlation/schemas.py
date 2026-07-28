from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from forensicx.modules.correlation.models import (
    CorrelationType,
    EntityType,
)


class CorrelationCreate(BaseModel):
    case_id: int

    source_type: EntityType
    source_id: int

    target_type: EntityType
    target_id: int

    correlation_type: CorrelationType

    confidence: float = 1.0

    details: dict[str, Any] = {}


class CorrelationUpdate(BaseModel):
    confidence: float | None = None
    details: dict[str, Any] | None = None


class CorrelationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int

    case_id: int

    source_type: EntityType
    source_id: int

    target_type: EntityType
    target_id: int

    correlation_type: CorrelationType

    confidence: float

    details: dict[str, Any]

    created_at: datetime


class CorrelationList(BaseModel):
    total: int
    items: list[CorrelationRead]


class CorrelationGraphNode(BaseModel):
    id: str
    type: EntityType
    label: str


class CorrelationGraphEdge(BaseModel):
    source: str
    target: str
    relationship: CorrelationType
    confidence: float


class CorrelationGraph(BaseModel):
    nodes: list[CorrelationGraphNode]
    edges: list[CorrelationGraphEdge]
