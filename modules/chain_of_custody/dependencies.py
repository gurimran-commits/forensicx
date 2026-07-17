"""
Dependency providers for the Chain of Custody module.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.orm import Session

from forensicx.modules.chain_of_custody.repository import (
    ChainOfCustodyRepository,
)
from forensicx.modules.chain_of_custody.service import (
    ChainOfCustodyService,
)
from forensicx.platform.dependencies import database_session


def custody_repository(
    session: Session = Depends(database_session)
) -> ChainOfCustodyRepository:
    """Provide a ChainOfCustodyRepository instance."""
    return ChainOfCustodyRepository(session)


def custody_service(
    repository: ChainOfCustodyRepository = Depends(custody_repository),
) -> ChainOfCustodyService:
    """Provide a ChainOfCustodyService instance."""
    return ChainOfCustodyService(repository)
