"""
Correlation Engine.

Responsible for discovering relationships between forensic entities.
"""

from __future__ import annotations

from forensicx.modules.correlation.models import (
    CorrelationType,
    EntityType,
)
from forensicx.modules.correlation.schemas import CorrelationCreate
from forensicx.modules.ioc.models import Ioc
from forensicx.modules.ioc.repository import IocRepository


class CorrelationEngine:
    """Engine responsible for discovering forensic relationships."""

    def __init__(self, ioc_repository: IocRepository) -> None:
        self._ioc_repository = ioc_repository
    
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
        
    
    def correlate_ioc(self, ioc: Ioc) -> list[CorrelationCreate]:
        """
        Discover matching IOCs and generate correlation candidates.
        """

        matches = self._ioc_repository.find_matching_with_case(
            ioc.indicator_type,
            ioc.value,
        )

        correlations: list[CorrelationCreate] = []

        for match, case_id in matches:

            # Ignore the IOC itself
            if match.id == ioc.id:
                continue

            if ioc.indicator_type == "ipv4":
                correlations.append(
                    self.correlate_ip(
                        case_id=case_id,
                        source_id=ioc.id,
                        target_id=match.id,
                        ip_address=ioc.value,
                    )
                )

            elif ioc.indicator_type == "domain":
                correlations.append(
                    self.correlate_domain(
                        case_id=case_id,
                        source_id=ioc.id,
                        target_id=match.id,
                        domain=ioc.value,
                    )
                )

            elif ioc.indicator_type == "email":
                correlations.append(
                    self.correlate_email(
                        case_id=case_id,
                        source_id=ioc.id,
                        target_id=match.id,
                        email=ioc.value,
                    )
                )

            elif ioc.indicator_type == "url":
                correlations.append(
                    self.correlate_url(
                        case_id=case_id,
                        source_id=ioc.id,
                        target_id=match.id,
                        url=ioc.value,
                    )
                )

            elif ioc.indicator_type in {"sha256", "sha1", "md5"}:
                correlations.append(
                    self.correlate_hash(
                        case_id=case_id,
                        source_id=ioc.id,
                        target_id=match.id,
                        sha256=ioc.value,
                    )
                )

        return correlations   
