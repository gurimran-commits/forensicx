"""
Registry for Threat Intelligence providers.
"""

from __future__ import annotations

from forensicx.modules.threat_intelligence.models import ThreatSource
from forensicx.modules.threat_intelligence.providers.abuseipdb import (
    AbuseIPDBProvider,
)
from forensicx.modules.threat_intelligence.providers.otx import (
    OTXProvider,
)
from forensicx.modules.threat_intelligence.providers.urlhaus import (
    URLHausProvider,
)
from forensicx.modules.threat_intelligence.providers.virustotal import (
    VirusTotalProvider,
)
from forensicx.platform.config import Settings


class ProviderRegistry:
    """Registry of available Threat Intelligence providers."""

    def __init__(self, settings: Settings) -> None:
        self._providers = {
            ThreatSource.VIRUSTOTAL: VirusTotalProvider(settings),
            ThreatSource.ABUSEIPDB: AbuseIPDBProvider(settings),
            ThreatSource.URLHAUS: URLHausProvider(settings),
            ThreatSource.OTX: OTXProvider(settings),
        }

    def all(self):
        """Return all registered providers."""
        return self._providers.items()
