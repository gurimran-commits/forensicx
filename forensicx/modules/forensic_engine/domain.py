"""Domain values for forensic analysis."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class AnalysisStatus(str, Enum):
    """Terminal state for an individual analyzer execution."""
    SUCCESS = "success"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class AnalyzerOutput:
    """Immutable, persistence-ready output produced by one analyzer."""
    analyzer_name: str
    analyzer_version: str
    status: AnalysisStatus
    findings: dict[str, Any]
    error_message: str | None = None
