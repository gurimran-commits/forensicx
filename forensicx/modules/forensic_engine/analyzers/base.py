"""Analyzer plugin contract."""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from forensicx.modules.forensic_engine.domain import AnalyzerOutput


class BaseAnalyzer(ABC):
    """Stable extension point for read-only forensic analyzer plugins."""

    name: str
    version = "1.0"

    @abstractmethod
    def analyze(self, evidence_path: Path) -> AnalyzerOutput:
        """Inspect ``evidence_path`` without modifying it and return findings."""

    def skipped(self, reason: str) -> AnalyzerOutput:
        """Build a consistent not-applicable result."""
        from forensicx.modules.forensic_engine.domain import AnalysisStatus
        return AnalyzerOutput(self.name, self.version, AnalysisStatus.SKIPPED, {"reason": reason})
