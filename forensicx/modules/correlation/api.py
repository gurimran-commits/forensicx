"""
Correlation API.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from forensicx.modules.correlation.dependencies import (
    get_correlation_service,
)
from forensicx.modules.correlation.schemas import (
    CorrelationCreate,
    CorrelationRead,
)
from forensicx.modules.correlation.service import (
    CorrelationService,
)

router = APIRouter(
    prefix="/correlations",
    tags=["Correlation"],
)


@router.post(
    "/",
    response_model=CorrelationRead,
    status_code=status.HTTP_201_CREATED,
)
def create_correlation(
    payload: CorrelationCreate,
    service: CorrelationService = Depends(get_correlation_service),
):
    """Create a correlation."""
    return service.create(payload)


@router.get(
    "/{correlation_id}",
    response_model=CorrelationRead,
)
def get_correlation(
    correlation_id: int,
    service: CorrelationService = Depends(get_correlation_service),
):
    """Return a correlation by ID."""

    correlation = service.get(correlation_id)

    if correlation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Correlation not found.",
        )

    return correlation


@router.get(
    "/case/{case_id}",
    response_model=list[CorrelationRead],
)
def list_case_correlations(
    case_id: int,
    service: CorrelationService = Depends(get_correlation_service),
):
    """Return correlations for a case."""
    return service.list_by_case(case_id)
@router.post(
    "/run/{evidence_id}",
    status_code=status.HTTP_200_OK,
)
def run_correlation(
    evidence_id: str,
    service: CorrelationService = Depends(get_correlation_service),
):
    """
    Run automatic correlation for one evidence item.
    """

    created = service.correlate_evidence(evidence_id)

    return {
        "message": "Correlation completed.",
        "correlations_created": created,
    }
