"""
REST API for Evidence Management.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    UploadFile,
    status,
)
from sqlalchemy.orm import Session

from forensicx.platform.database import get_session
from forensicx.platform.config import get_settings

from forensicx.modules.evidence.schemas import (
    EvidenceDetail,
    EvidenceListItem,
    EvidenceUploadResponse,
)

from forensicx.modules.evidence.service import EvidenceService

router = APIRouter(
    prefix="/cases/{case_id}/evidence",
    tags=["Evidence"],
)
