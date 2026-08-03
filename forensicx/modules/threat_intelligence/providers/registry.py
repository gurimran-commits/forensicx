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


class ProviderRegistry:
    """Registry of available Threat Intelligence providers."""

    def __init__(self) -> None:
        self._providers = {
            ThreatSource.VIRUSTOTAL: VirusTotalProvider(),
            ThreatSource.ABUSEIPDB: AbuseIPDBProvider(),
            ThreatSource.URLHAUS: URLHausProvider(),
            ThreatSource.OTX: OTXProvider(),
        }

    def all(self):
        """Return all registered providers."""
        return self._providers.items()
