"""Persistent extracted indicators of compromise."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from forensicx.platform.models import Base


class Ioc(Base):
    """One normalized indicator extracted from stored evidence."""

    __tablename__ = "iocs"
    __table_args__ = (
        UniqueConstraint("evidence_id", "indicator_type", "value", name="uq_iocs_evidence_type_value"),
        Index("ix_iocs_evidence_created", "evidence_id", "created_at"),
        Index("ix_iocs_type_value", "indicator_type", "value"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    evidence_id: Mapped[str] = mapped_column(String(36), ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
