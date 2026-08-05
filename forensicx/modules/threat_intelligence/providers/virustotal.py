"""
VirusTotal provider.
"""

from __future__ import annotations

import requests

from forensicx.modules.ioc.models import Ioc
from forensicx.modules.threat_intelligence.providers.base import (
    ThreatIntelProvider,
)
from forensicx.platform.config import Settings


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal Threat Intelligence provider."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)

    @property
    def name(self) -> str:
        return "virustotal"

    def lookup(self, ioc: Ioc) -> dict:
        """
        Query VirusTotal for a supported IOC.
        """

        api_key = self.settings.virustotal_api_key

        if not api_key:
            return {
                "verdict": "unknown",
                "score": 0,
                "details": {
                    "error": "VirusTotal API key not configured",
                },
            }

        headers = {
            "x-apikey": api_key,
        }

        endpoint = self._endpoint_for_ioc(ioc)

        if endpoint is None:
            return {
                "verdict": "unsupported",
                "score": 0,
                "details": {
                    "reason": "IOC type not supported",
                },
            }

        try:
            response = requests.get(
                f"{self.BASE_URL}/{endpoint}",
                headers=headers,
                timeout=20,
            )

            response.raise_for_status()

            data = response.json()

            return self._normalize(data)

        except requests.RequestException as exc:
            return {
                "verdict": "error",
                "score": 0,
                "details": {
                    "error": str(exc),
                },
            }

    def _endpoint_for_ioc(self, ioc: Ioc) -> str | None:
        """Return the VirusTotal endpoint for an IOC."""

        if ioc.indicator_type == "ipv4":
            return f"ip_addresses/{ioc.value}"

        if ioc.indicator_type == "domain":
            return f"domains/{ioc.value}"

        if ioc.indicator_type == "url":
            return None

        if ioc.indicator_type in ("sha256", "md5", "sha1"):
            return f"files/{ioc.value}"

        return None

    def _normalize(self, payload: dict) -> dict:
        """Normalize VirusTotal responses."""

        attributes = payload.get("data", {}).get("attributes", {})

        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        score = malicious + suspicious

        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return {
            "verdict": verdict,
            "score": score,
            "details": {
                "analysis_stats": stats,
            },
        }
