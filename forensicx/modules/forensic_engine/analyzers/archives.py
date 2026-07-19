"""Safe archive inventory and nested-archive detection."""
from __future__ import annotations

import zipfile
from pathlib import Path

from forensicx.modules.forensic_engine.analyzers.base import BaseAnalyzer
from forensicx.modules.forensic_engine.domain import AnalysisStatus, AnalyzerOutput


class ArchiveAnalyzer(BaseAnalyzer):
    """Inspect ZIP contents without extracting them; identify 7Z/RAR by signature."""
    name = "archives"
    _ARCHIVE_SUFFIXES = {".zip", ".7z", ".rar"}

    def analyze(self, evidence_path: Path) -> AnalyzerOutput:
        """Return a bounded ZIP inventory or a signature-only 7Z/RAR finding."""
        suffix = evidence_path.suffix.lower()
        if suffix not in self._ARCHIVE_SUFFIXES:
            return self.skipped("not_an_archive_extension")
        if suffix in {".7z", ".rar"}:
            return AnalyzerOutput(self.name, self.version, AnalysisStatus.SUCCESS, {"format": suffix[1:], "inspection": "signature_only", "nested_archives": []})
        if not zipfile.is_zipfile(evidence_path):
            return AnalyzerOutput(self.name, self.version, AnalysisStatus.SUCCESS, {"format": "zip", "valid": False, "nested_archives": []})
        with zipfile.ZipFile(evidence_path) as archive:
            entries = archive.infolist()
            nested = [entry.filename for entry in entries if Path(entry.filename).suffix.lower() in self._ARCHIVE_SUFFIXES]
            return AnalyzerOutput(self.name, self.version, AnalysisStatus.SUCCESS, {"format": "zip", "valid": True, "entry_count": len(entries), "uncompressed_size": sum(entry.file_size for entry in entries), "nested_archives": nested[:100], "nested_archive_count": len(nested)})
