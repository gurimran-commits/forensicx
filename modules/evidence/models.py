"""
Database models for evidence management.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import (
    DateTime,
    Enum as SqlEnum,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from forensicx.platform.models import Base


class EvidenceStatus(str, Enum):
    """Current lifecycle status of an evidence item."""

    UPLOADED = "uploaded"
    ANALYZING = "analyzing"
    ANALYZED = "analyzed"
    ARCHIVED = "archived"


class Evidence(Base):
    """Represents a single evidence file."""

    __tablename__ = "evidence"

    __table_args__ = (
        Index("ix_evidence_sha256", "sha256"),
        Index("ix_evidence_case_id", "case_id"),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    case_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )

    original_filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    stored_filename: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
    )

    storage_path: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )

    file_extension: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    mime_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    magic_type: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    file_size: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    md5: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    sha1: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
    )

    sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    tags: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    uploaded_by: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
    )

    status: Mapped[EvidenceStatus] = mapped_column(
        SqlEnum(EvidenceStatus),
        default=EvidenceStatus.UPLOADED,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    case: Mapped["CaseModel"] = relationship("CaseModel", back_populates="evidence")
    custody_events = relationship(
        "ChainOfCustody",
        back_populates="evidence",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
