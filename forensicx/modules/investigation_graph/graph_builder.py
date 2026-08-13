"""
Investigation Graph Builder.
"""

from __future__ import annotations

from forensicx.modules.investigation_graph.models import (
    GraphEdge,
    GraphNode,
    EdgeType,
    NodeType,
)

from forensicx.modules.correlation.models import EntityType

class InvestigationGraphBuilder:
    """Build investigation graphs."""

    def __init__(
        self,
        case_repository,
        evidence_repository,
        ioc_repository,
        correlation_repository,
        threat_repository,
    ):
        self._cases = case_repository
        self._evidence = evidence_repository
        self._iocs = ioc_repository
        self._correlations = correlation_repository
        self._threats = threat_repository

    def build_case_graph(
        self,
        case_id: int,
    ) -> dict:

        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []
        seen_nodes: set[str] = set()

        case = self._cases.get_by_id(case_id)

        if case is None:
            return {
                "nodes": [],
                "edges": [],
            }

        case_node = GraphNode(
            id=f"case-{case.id}",
            type=NodeType.CASE,
            label=case.case_number,
        )

        if case_node.id not in seen_nodes:
            nodes.append(case_node)
            seen_nodes.add(case_node.id)

        evidence_items = self._evidence.list_by_case(case.id)

        for evidence in evidence_items:

            evidence_node = GraphNode(
                id=f"evidence-{evidence.id}",
                type=NodeType.EVIDENCE,
                label=evidence.original_filename,
            )

            if evidence_node.id not in seen_nodes:
                nodes.append(evidence_node)
                seen_nodes.add(evidence_node.id)

            edges.append(
                GraphEdge(
                    source=f"case-{case.id}",
                    target=f"evidence-{evidence.id}",
                    type=EdgeType.CASE_HAS_EVIDENCE,
                )
            )

            iocs = self._iocs.list_for_evidence(
                evidence.id,
                offset=0,
                limit=10000,
            )

            for ioc in iocs:

                node = GraphNode(
                    id=f"ioc-{ioc.id}",
                    type=NodeType.IOC,
                    label=ioc.value,
                )
                correlations = self._correlations.list_by_source(
                    source_type=EntityType.IOC,
                    source_id=ioc.id,
                )

                for correlation in correlations:

                    edges.append(
                        GraphEdge(
                            source=f"ioc-{correlation.source_id}",
                            target=f"ioc-{correlation.target_id}",
                            type=EdgeType.IOC_MATCH,
                        )
                    )
                if node.id not in seen_nodes:
                    nodes.append(node)
                    seen_nodes.add(node.id)
                edges.append(
                    GraphEdge(
                        source=f"evidence-{evidence.id}",
                        target=f"ioc-{ioc.id}",
                        type=EdgeType.EVIDENCE_HAS_IOC,
                    )
                )

                intel_records = self._threats.list_by_ioc(
                    ioc.id,
                    offset=0,
                    limit=10000,
                )

                for intel in intel_records:

                    threat_node = GraphNode(
                        id=f"threat-{intel.id}",
                        type=NodeType.THREAT,
                        label=intel.source.value,
                    )

                    if threat_node.id not in seen_nodes:
                        nodes.append(threat_node)
                        seen_nodes.add(threat_node.id)

                    edges.append(
                        GraphEdge(
                            source=f"ioc-{ioc.id}",
                            target=f"threat-{intel.id}",
                            type=EdgeType.IOC_THREAT,
                        )
                    )

        return {
            "nodes": nodes,
            "edges": edges,
        }
