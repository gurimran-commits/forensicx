"""
Dependency providers for the Correlation module.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.orm import Session

from forensicx.platform.dependencies import database_session
from forensicx.modules.correlation.service import CorrelationService


def get_correlation_service(
    session: Session = Depends(database_session),
) -> CorrelationService:
    """Return a CorrelationService instance."""
    return CorrelationService(session)
