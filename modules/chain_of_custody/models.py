"""
Database models for the Chain of Custody module.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from sqlalchemy import (
    DateTime,
    Enum as SqlEnum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from forensicx.platform.models import Base


class CustodyAction(str, Enum):
    """Supported chain of custody actions."""

    UPLOADED = "uploaded"
    DOWNLOADED = "downloaded"
    VERIFIED = "verified"
    ANALYZED = "analyzed"
    ARCHIVED = "archived"
    DELETED = "deleted"
    EXPORTED = "exported"
    UPDATED = "updated"


class ChainOfCustody(Base):
    """Immutable audit record for evidence actions."""

    __tablename__ = "chain_of_custody"

    __table_args__ = (
        Index("ix_chain_of_custody_evidence", "evidence_id"),
        Index("ix_chain_of_custody_timestamp", "performed_at"),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    evidence_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence.id", ondelete="CASCADE"),
        nullable=False,
    )

    action: Mapped[CustodyAction] = mapped_column(
        SqlEnum(CustodyAction),
        nullable=False,
    )

    performed_by: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
    )

    location: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    performed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    evidence = relationship(
        "Evidence",
        back_populates="custody_events",
    )
