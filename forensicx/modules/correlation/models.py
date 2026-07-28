from __future__ import annotations

from datetime import datetime
from enum import Enum

from sqlalchemy import (
    DateTime,
    Enum as SQLEnum,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from forensicx.platform.models import Base


class CorrelationType(str, Enum):
    SHARES_IP = "shares_ip"
    SHARES_DOMAIN = "shares_domain"
    SHARES_HASH = "shares_hash"
    SHARES_EMAIL = "shares_email"
    SHARES_URL = "shares_url"
    SAME_FILE = "same_file"
    RELATED_IOC = "related_ioc"
    CUSTOM = "custom"


class EntityType(str, Enum):
    CASE = "case"
    EVIDENCE = "evidence"
    IOC = "ioc"
    ANALYSIS = "analysis"


class Correlation(Base):
    __tablename__ = "correlations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    case_id: Mapped[int] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    source_type: Mapped[EntityType] = mapped_column(
        SQLEnum(EntityType),
        nullable=False,
    )

    source_id: Mapped[int] = mapped_column(nullable=False)

    target_type: Mapped[EntityType] = mapped_column(
        SQLEnum(EntityType),
        nullable=False,
    )

    target_id: Mapped[int] = mapped_column(nullable=False)

    correlation_type: Mapped[CorrelationType] = mapped_column(
        SQLEnum(CorrelationType),
        nullable=False,
    )

    confidence: Mapped[float] = mapped_column(
        Float,
        default=1.0,
        nullable=False,
    )

    details: Mapped[dict] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
