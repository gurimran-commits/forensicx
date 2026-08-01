"""
Schemas for investigation graph responses.
"""

from __future__ import annotations

from pydantic import BaseModel


class GraphNode(BaseModel):
    id: str
    label: str
    type: str


class GraphEdge(BaseModel):
    source: str
    target: str
    label: str


class InvestigationGraph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
