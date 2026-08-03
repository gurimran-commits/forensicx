"""
Dependency providers for Threat Intelligence.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.orm import Session

from forensicx.platform.dependencies import database_session
from forensicx.modules.threat_intelligence.service import ThreatIntelService


def get_threat_intel_service(
    session: Session = Depends(database_session),
) -> ThreatIntelService:
    """Return a request-scoped ThreatIntelService."""
    return ThreatIntelService(session)
