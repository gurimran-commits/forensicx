"""
Dependency providers for the Correlation module.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.orm import Session

from forensicx.platform.database import get_db

from forensicx.modules.correlation.service import CorrelationService


def get_correlation_service(
    session: Session = Depends(get_db),
) -> CorrelationService:
    """Return a CorrelationService instance."""
    return CorrelationService(session)
