"""
Graph models.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class NodeType(str, Enum):
    CASE = "case"
    EVIDENCE = "evidence"
    IOC = "ioc"
    THREAT = "threat"


class EdgeType(str, Enum):
    CASE_HAS_EVIDENCE = "case_has_evidence"
    EVIDENCE_HAS_IOC = "evidence_has_ioc"
    IOC_MATCH = "ioc_match"
    IOC_THREAT = "ioc_threat"


class GraphNode(BaseModel):
    id: str
    type: NodeType
    label: str
    metadata: dict = {}


class GraphEdge(BaseModel):
    source: str
    target: str
    type: EdgeType
