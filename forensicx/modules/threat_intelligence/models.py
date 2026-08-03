"""
Database models for Threat Intelligence enrichment.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from sqlalchemy import (
    DateTime,
    Enum as SQLEnum,
    ForeignKey,
    Integer,
    JSON,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from forensicx.platform.models import Base


class ThreatSource(str, Enum):
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    URLHAUS = "urlhaus"
    OTX = "otx"


class ThreatIntel(Base):
    __tablename__ = "threat_intelligence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    ioc_id: Mapped[int] = mapped_column(
        ForeignKey("iocs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    source: Mapped[ThreatSource] = mapped_column(
        SQLEnum(ThreatSource),
        nullable=False,
    )

    verdict: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    score: Mapped[int] = mapped_column(
        Integer,
        default=0,
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
