"""
Threat Intelligence API.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from forensicx.modules.threat_intelligence.dependencies import (
    get_threat_intel_service,
)
from forensicx.modules.threat_intelligence.schemas import (
    ThreatIntelRead,
)
from forensicx.modules.threat_intelligence.service import (
    ThreatIntelService,
)

router = APIRouter(
    prefix="/threat-intelligence",
    tags=["Threat Intelligence"],
)


@router.post("/ioc/{ioc_id}")
def enrich_ioc(
    ioc_id: int,
    service: ThreatIntelService = Depends(get_threat_intel_service),
):
    """Enrich one IOC using all configured providers."""
    results = service.enrich_ioc(ioc_id)

    return {
        "ioc_id": ioc_id,
        "records_created": len(results),
        "items": [ThreatIntelRead.model_validate(item) for item in results],
    }
