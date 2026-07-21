"""REST API for extracting indicators of compromise from evidence."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Path, Query

from forensicx.modules.ioc.dependencies import ioc_extraction_service
from forensicx.modules.ioc.schemas import IocExtractionResponse, IocListResponse, IocRead
from forensicx.modules.ioc.service import IocExtractionService
from forensicx.platform.security import Principal, require_role


router = APIRouter(prefix="/forensics", tags=["forensics"])


@router.post("/evidence/{evidence_id}/iocs", response_model=IocExtractionResponse, summary="Extract supported indicators from evidence")
def extract_evidence_iocs(
    evidence_id: str = Path(description="Evidence UUID."),
    principal: Principal = Depends(require_role("iocs:write")),
    service: IocExtractionService = Depends(ioc_extraction_service),
) -> IocExtractionResponse:
    """Extract and persist IPv4, domains, URLs, emails, and file hashes."""
    _ = principal
    items = service.extract(evidence_id)
    return IocExtractionResponse(evidence_id=evidence_id, items=[IocRead.model_validate(item) for item in items])


@router.get("/evidence/{evidence_id}/iocs", response_model=IocListResponse, summary="List indicators extracted from evidence")
def list_evidence_iocs(
    evidence_id: str = Path(description="Evidence UUID."),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(require_role("iocs:read")),
    service: IocExtractionService = Depends(ioc_extraction_service),
) -> IocListResponse:
    """List persisted indicators for one evidence item."""
    _ = principal
    items = service.list(evidence_id, offset=offset, limit=limit)
    return IocListResponse(items=[IocRead.model_validate(item) for item in items], limit=limit, offset=offset)
