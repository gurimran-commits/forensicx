"""
Correlation Engine.

Responsible for discovering relationships between forensic entities.
"""

from __future__ import annotations

from forensicx.modules.correlation.models import (
    Correlation,
    CorrelationType,
    EntityType,
)
from forensicx.modules.correlation.schemas import CorrelationCreate


class CorrelationEngine:
    """Engine responsible for discovering forensic relationships."""

    def correlate_ip(
        self,
        *,
        case_id: int,
        source_id: int,
        target_id: int,
        ip_address: str,
    ) -> CorrelationCreate:
        """Create an IP correlation."""

        return CorrelationCreate(
            case_id=case_id,
            source_type=EntityType.IOC,
            source_id=source_id,
            target_type=EntityType.IOC,
            target_id=target_id,
            correlation_type=CorrelationType.SAME_IP,
            confidence=0.95,
            details={
                "ip": ip_address,
            },
        )

    def correlate_hash(
        self,
        *,
        case_id: int,
        source_id: int,
        target_id: int,
        sha256: str,
    ) -> CorrelationCreate:
        """Create a file hash correlation."""

        return CorrelationCreate(
            case_id=case_id,
            source_type=EntityType.EVIDENCE,
            source_id=source_id,
            target_type=EntityType.EVIDENCE,
            target_id=target_id,
            correlation_type=CorrelationType.SAME_HASH,
            confidence=1.0,
            details={
                "sha256": sha256,
            },
        )

    def correlate_domain(
        self,
        *,
        case_id: int,
        source_id: int,
        target_id: int,
        domain: str,
    ) -> CorrelationCreate:
        """Create a domain correlation."""

        return CorrelationCreate(
            case_id=case_id,
            source_type=EntityType.IOC,
            source_id=source_id,
            target_type=EntityType.IOC,
            target_id=target_id,
            correlation_type=CorrelationType.SAME_DOMAIN,
            confidence=0.90,
            details={
                "domain": domain,
            },
        )

    def correlate_email(
        self,
        *,
        case_id: int,
        source_id: int,
        target_id: int,
        email: str,
    ) -> CorrelationCreate:
        """Create an email correlation."""

        return CorrelationCreate(
            case_id=case_id,
            source_type=EntityType.IOC,
            source_id=source_id,
            target_type=EntityType.IOC,
            target_id=target_id,
            correlation_type=CorrelationType.SAME_EMAIL,
            confidence=0.90,
            details={
                "email": email,
            },
        )

    def correlate_url(
        self,
        *,
        case_id: int,
        source_id: int,
        target_id: int,
        url: str,
    ) -> CorrelationCreate:
        """Create a URL correlation."""

        return CorrelationCreate(
            case_id=case_id,
            source_type=EntityType.IOC,
            source_id=source_id,
            target_type=EntityType.IOC,
            target_id=target_id,
            correlation_type=CorrelationType.SAME_URL,
            confidence=0.90,
            details={
                "url": url,
            },
        )
