"""
URLHaus provider.
"""

from __future__ import annotations

from forensicx.modules.ioc.models import Ioc
from forensicx.modules.threat_intelligence.providers.base import (
    ThreatIntelProvider,
)
from forensicx.platform.config import Settings


class URLHausProvider(ThreatIntelProvider):

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)

    @property
    def name(self) -> str:
        return "urlhaus"

    def lookup(self, ioc: Ioc) -> dict:
        return {
            "verdict": "unknown",
            "score": 0,
            "details": {},
        }
