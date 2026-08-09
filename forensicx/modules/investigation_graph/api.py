"""
Investigation Graph API.
"""

from fastapi import APIRouter, Depends

from forensicx.modules.investigation_graph.dependencies import (
    get_graph_service,
)
from forensicx.modules.investigation_graph.service import (
    InvestigationGraphService,
)

from forensicx.modules.investigation_graph.schemas import InvestigationGraph

router = APIRouter(
    prefix="/graph",
    tags=["Investigation Graph"],
)


@router.get(
    "/case/{case_id}",
    response_model=InvestigationGraph,
)
def build_case_graph(
    case_id: int,
    service: InvestigationGraphService = Depends(get_graph_service),
):
    """Return the investigation graph for a case."""

    return service.build_case_graph(case_id)
