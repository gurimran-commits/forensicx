"""REST API for the Digital Forensics Engine."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Path, Query

from forensicx.modules.forensic_engine.dependencies import forensic_analysis_service
from forensicx.modules.forensic_engine.schemas import ForensicAnalysisListResponse, ForensicAnalysisRead, ForensicAnalysisRunResponse
from forensicx.modules.forensic_engine.service import ForensicAnalysisService
from forensicx.platform.security import Principal, require_role

router = APIRouter(prefix="/forensics", tags=["forensics"])


@router.post("/evidence/{evidence_id}/analysis", response_model=ForensicAnalysisRunResponse, summary="Analyze immutable evidence", description="Runs every discovered read-only forensic analyzer. Individual analyzer failures are stored and do not stop other analyzers.")
def analyze_evidence(evidence_id: str = Path(description="Evidence UUID."), principal: Principal = Depends(require_role("forensics:read")), service: ForensicAnalysisService = Depends(forensic_analysis_service)) -> ForensicAnalysisRunResponse:
    """Create a separately persisted result for each analyzer."""
    results = service.analyze(evidence_id, principal.subject)
    return ForensicAnalysisRunResponse(evidence_id=evidence_id, results=[ForensicAnalysisRead.model_validate(item) for item in results])


@router.get("/evidence/{evidence_id}/analysis", response_model=ForensicAnalysisListResponse, summary="Get forensic analysis history", description="Returns historical analysis results; it never changes evidence or evidence hashes.")
def list_analysis(evidence_id: str = Path(description="Evidence UUID."), limit: int = Query(default=50, ge=1, le=100), offset: int = Query(default=0, ge=0), principal: Principal = Depends(require_role("forensics:read")), service: ForensicAnalysisService = Depends(forensic_analysis_service)) -> ForensicAnalysisListResponse:
    """List forensic result history for one evidence item."""
    _ = principal
    items = service.history(evidence_id, offset=offset, limit=limit)
    return ForensicAnalysisListResponse(items=[ForensicAnalysisRead.model_validate(item) for item in items], limit=limit, offset=offset)
