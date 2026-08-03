"""
Base interface for Threat Intelligence providers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from forensicx.modules.ioc.models import Ioc


class ThreatIntelProvider(ABC):
    """Base class implemented by every Threat Intelligence provider."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name."""

    @abstractmethod
    def lookup(self, ioc: Ioc) -> dict:
        """
        Query one IOC.

        Returns a normalized dictionary that the service
        can store without knowing provider-specific details.
        """
