"""
Pydantic schemas for the Evidence module.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from forensicx.modules.evidence.models import EvidenceStatus


class EvidenceBase(BaseModel):
    """Common evidence fields."""

    description: Optional[str] = Field(
        default=None,
        max_length=2000,
        description="Investigator notes about this evidence.",
    )

    tags: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Comma-separated tags.",
    )


class EvidenceUploadResponse(BaseModel):
    """Response returned after a successful upload."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID

    case_id: int

    original_filename: str

    stored_filename: str

    file_extension: str

    mime_type: str

    file_size: int

    md5: str

    sha1: str

    sha256: str

    status: EvidenceStatus

    uploaded_by: str

    created_at: datetime


class EvidenceDetail(EvidenceUploadResponse):
    """Complete evidence details."""

    storage_path: str

    magic_type: Optional[str]

    description: Optional[str]

    tags: Optional[str]

    updated_at: datetime


class EvidenceListItem(BaseModel):
    """Evidence shown inside case listings."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID

    original_filename: str

    file_extension: str

    file_size: int

    status: EvidenceStatus

    created_at: datetime


class EvidenceListResponse(BaseModel):
    """Paginated case evidence list response."""

    items: list[EvidenceListItem]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class EvidenceHashResponse(BaseModel):
    """Cryptographic hashes."""

    md5: str

    sha1: str

    sha256: str


class EvidenceMetadataResponse(BaseModel):
    """Metadata extracted from uploaded evidence."""

    filename: str

    extension: str

    mime_type: str

    magic_type: Optional[str]

    file_size: int

    created_at: datetime


class EvidenceValidationResponse(BaseModel):
    """Result of validating an evidence upload without storing it."""

    filename: str
    extension: str
    file_size: int = Field(ge=0)


class EvidenceUpdateRequest(EvidenceBase):
    """Fields that investigators may update."""

    pass
