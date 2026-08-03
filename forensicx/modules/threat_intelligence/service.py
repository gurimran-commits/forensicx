"""
Service layer for Threat Intelligence.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from forensicx.modules.ioc.repository import IocRepository
from forensicx.modules.threat_intelligence.models import (
    ThreatIntel,
    ThreatSource,
)

from forensicx.modules.threat_intelligence.providers.registry import (
    ProviderRegistry,
)

from forensicx.modules.threat_intelligence.repository import (
    ThreatIntelRepository,
)


class ThreatIntelService:
    """Business logic for Threat Intelligence."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._repository = ThreatIntelRepository(session)
        self._ioc_repository = IocRepository(session)

        self._registry = ProviderRegistry()
        
    def enrich_ioc(
        self,
        ioc_id: int,
    ) -> list[ThreatIntel]:
        """
        Query every configured provider for one IOC.
        """

        ioc = self._ioc_repository.get_by_id(ioc_id)

        if ioc is None:
            return []

        created: list[ThreatIntel] = []

        for source, provider in self._registry.all():

            if self._repository.exists(ioc.id, source):
                continue

            result = provider.lookup(ioc)

            intel = ThreatIntel(
                ioc_id=ioc.id,
                source=source,
                verdict=result["verdict"],
                score=result["score"],
                details=result["details"],
            )

            self._repository.create(intel)
                created.append(intel)

        if created:
            self._session.commit()

        return created
