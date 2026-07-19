"""Persistent, append-only forensic analysis results."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Enum as SqlEnum, ForeignKey, Index, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from forensicx.modules.forensic_engine.domain import AnalysisStatus
from forensicx.platform.models import Base


class ForensicAnalysisResult(Base):
    """One analyzer result linked to, but never mutating, an evidence item."""
    __tablename__ = "forensic_analysis_results"
    __table_args__ = (Index("ix_forensic_analysis_evidence_created", "evidence_id", "created_at"), Index("ix_forensic_analysis_analyzer", "analyzer_name"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    evidence_id: Mapped[str] = mapped_column(String(36), ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False)
    analyzer_name: Mapped[str] = mapped_column(String(100), nullable=False)
    analyzer_version: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[AnalysisStatus] = mapped_column(SqlEnum(AnalysisStatus), nullable=False)
    findings: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    analyzed_by: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
