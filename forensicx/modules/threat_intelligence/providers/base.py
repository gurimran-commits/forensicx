"""
Base interface for Threat Intelligence providers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from forensicx.modules.ioc.models import Ioc
from forensicx.platform.config import Settings


class ThreatIntelProvider(ABC):
    """Base class implemented by every Threat Intelligence provider."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name."""

    @abstractmethod
    def lookup(self, ioc: Ioc) -> dict:
        """Query one IOC."""
