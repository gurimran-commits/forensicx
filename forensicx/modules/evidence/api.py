"""Evidence management REST API routes."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, Query, Response, UploadFile, status
from fastapi.responses import FileResponse

from forensicx.modules.evidence.dependencies import evidence_service
from forensicx.modules.evidence.schemas import (
    EvidenceHashResponse,
    EvidenceListItem,
    EvidenceListResponse,
    EvidenceMetadataResponse,
    EvidenceUploadResponse,
    EvidenceValidationResponse,
)
from forensicx.modules.evidence.service import EvidenceService
from forensicx.platform.security import Principal, require_role


router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.post(
    "",
    response_model=EvidenceUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload case evidence",
    description="Validates, stores, hashes, and registers an evidence file for an investigation case.",
)
async def upload_evidence(
    case_id: int = Form(ge=1, description="Database identifier of the investigation case that owns the evidence."),
    file: UploadFile = File(description="Evidence file to validate, store, and hash."),
    description: str | None = Form(default=None, max_length=2000, description="Investigator notes about this evidence."),
    tags: str | None = Form(default=None, max_length=500, description="Comma-separated evidence tags."),
    principal: Principal = Depends(require_role("evidence:write")),
    service: EvidenceService = Depends(evidence_service),
) -> EvidenceUploadResponse:
    """Upload and register an evidence file."""
    evidence = await service.upload(
        case_id=case_id,
        uploaded_by=principal.subject,
        upload=file,
        description=description,
        tags=tags,
    )
    return EvidenceUploadResponse.model_validate(evidence)


@router.post(
    "/validate",
    response_model=EvidenceValidationResponse,
    summary="Validate evidence upload",
    description="Validates the filename, extension, and size of an evidence file without storing it.",
)
async def validate_evidence_upload(
    file: UploadFile = File(description="Evidence file to validate without storing."),
    principal: Principal = Depends(require_role("evidence:write")),
    service: EvidenceService = Depends(evidence_service),
) -> EvidenceValidationResponse:
    """Validate an evidence upload without persisting it."""
    _ = principal
    filename, extension, file_size = await service.validate_upload(file)
    return EvidenceValidationResponse(filename=filename, extension=extension, file_size=file_size)


@router.get(
    "",
    response_model=EvidenceListResponse,
    summary="List case evidence",
    description="Returns paginated evidence registered to an investigation case.",
)
async def list_evidence(
    case_id: int = Query(ge=1, description="Database identifier of the owning investigation case."),
    limit: int = Query(default=50, ge=1, le=100, description="Maximum evidence items returned."),
    offset: int = Query(default=0, ge=0, description="Pagination offset."),
    principal: Principal = Depends(require_role("evidence:read")),
    service: EvidenceService = Depends(evidence_service),
) -> EvidenceListResponse:
    """List evidence for one case."""
    _ = principal
    items, total = service.list_case_evidence(case_id, offset=offset, limit=limit)
    return EvidenceListResponse(
        items=[EvidenceListItem.model_validate(item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{evidence_id}/download",
    response_class=FileResponse,
    summary="Download evidence",
    description="Streams an evidence file after verifying that its registered storage object is available.",
)
async def download_evidence(
    evidence_id: UUID,
    principal: Principal = Depends(require_role("evidence:read")),
    service: EvidenceService = Depends(evidence_service),
) -> FileResponse:
    """Download one evidence file."""
    _ = principal
    evidence = service.download(str(evidence_id))
    return FileResponse(
        evidence.storage_path,
        media_type=evidence.mime_type,
        filename=evidence.original_filename,
    )


@router.get(
    "/{evidence_id}/metadata",
    response_model=EvidenceMetadataResponse,
    summary="Read evidence metadata",
    description="Returns the registered file metadata for one evidence item.",
)
async def get_evidence_metadata(
    evidence_id: UUID,
    principal: Principal = Depends(require_role("evidence:read")),
    service: EvidenceService = Depends(evidence_service),
) -> EvidenceMetadataResponse:
    """Return registered evidence metadata."""
    _ = principal
    evidence = service.get(str(evidence_id))
    return EvidenceMetadataResponse(
        filename=evidence.original_filename,
        extension=evidence.file_extension,
        mime_type=evidence.mime_type,
        magic_type=evidence.magic_type,
        file_size=evidence.file_size,
        created_at=evidence.created_at,
    )


@router.get(
    "/{evidence_id}/hashes",
    response_model=EvidenceHashResponse,
    summary="Read evidence hashes",
    description="Returns the registered MD5, SHA-1, and SHA-256 hashes for one evidence item.",
)
async def get_evidence_hashes(
    evidence_id: UUID,
    principal: Principal = Depends(require_role("evidence:read")),
    service: EvidenceService = Depends(evidence_service),
) -> EvidenceHashResponse:
    """Return registered evidence hashes."""
    _ = principal
    evidence = service.get(str(evidence_id))
    return EvidenceHashResponse(md5=evidence.md5, sha1=evidence.sha1, sha256=evidence.sha256)


@router.delete(
    "/{evidence_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Soft-delete evidence registration",
    description="Archives the evidence registration while retaining its database row and stored file.",
)
async def delete_evidence(
    evidence_id: UUID,
    principal: Principal = Depends(require_role("evidence:write")),
    service: EvidenceService = Depends(evidence_service),
) -> Response:
    """Soft-delete one evidence registration without removing the stored file."""
    service.delete(str(evidence_id), performed_by=principal.subject)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
