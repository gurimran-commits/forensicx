"""
Dependency providers for Investigation Graph.
"""

from fastapi import Depends
from sqlalchemy.orm import Session

from forensicx.platform.dependencies import database_session

from forensicx.modules.investigation_graph.service import (
    InvestigationGraphService,
)


def get_graph_service(
    session: Session = Depends(database_session),
) -> InvestigationGraphService:

    return InvestigationGraphService(session)
