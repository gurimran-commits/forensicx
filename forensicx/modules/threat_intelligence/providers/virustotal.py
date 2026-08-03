"""
VirusTotal provider.
"""

from __future__ import annotations

from forensicx.modules.ioc.models import Ioc
from forensicx.modules.threat_intelligence.providers.base import (
    ThreatIntelProvider,
)


class VirusTotalProvider(ThreatIntelProvider):

    @property
    def name(self) -> str:
        return "virustotal"

    def lookup(self, ioc: Ioc) -> dict:
        """
        Temporary implementation.

        Real API integration comes later.
        """

        return {
            "verdict": "unknown",
            "score": 0,
            "details": {},
        }
