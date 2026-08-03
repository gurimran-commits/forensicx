"""
AlienVault OTX provider.
"""

from __future__ import annotations

from forensicx.modules.ioc.models import Ioc
from forensicx.modules.threat_intelligence.providers.base import (
    ThreatIntelProvider,
)


class OTXProvider(ThreatIntelProvider):

    @property
    def name(self) -> str:
        return "otx"

    def lookup(self, ioc: Ioc) -> dict:

        return {
            "verdict": "unknown",
            "score": 0,
            "details": {},
        }
