"""
Schemas for Investigation Graph.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from forensicx.modules.investigation_graph.models import (
    GraphEdge,
    GraphNode,
)


class InvestigationGraph(BaseModel):
    """Complete graph returned for an investigation."""

    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
