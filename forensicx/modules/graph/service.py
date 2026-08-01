"""
Investigation Graph Service.
"""

from __future__ import annotations

from forensicx.modules.graph.schemas import (
    InvestigationGraph,
    GraphNode,
    GraphEdge,
)


class GraphService:
    """Build investigation graphs."""

    def __init__(self) -> None:
        pass

    def case_graph(
        self,
        case_id: int,
    ) -> InvestigationGraph:
        """
        Return a graph for one investigation case.
        """

        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []

        return InvestigationGraph(
            nodes=nodes,
            edges=edges,
        )
