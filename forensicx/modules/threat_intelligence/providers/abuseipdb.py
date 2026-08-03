"""
AbuseIPDB provider.
"""

from __future__ import annotations

from forensicx.modules.ioc.models import Ioc
from forensicx.modules.threat_intelligence.providers.base import (
    ThreatIntelProvider,
)


class AbuseIPDBProvider(ThreatIntelProvider):

    @property
    def name(self) -> str:
        return "abuseipdb"

    def lookup(self, ioc: Ioc) -> dict:

        return {
            "verdict": "unknown",
            "score": 0,
            "details": {},
        }
