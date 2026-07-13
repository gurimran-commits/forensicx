"""SQLAlchemy models for the dashboard module."""

from __future__ import annotations

from sqlalchemy import CheckConstraint, Index, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from forensicx.platform.models import Base


class DashboardSnapshotModel(Base):
    """Persisted dashboard snapshot."""

    __tablename__ = "dashboard_snapshots"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_dashboard_snapshots_singleton"),
        Index("idx_dashboard_snapshots_generated_at", "generated_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    generated_at: Mapped[str] = mapped_column(Text, nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
