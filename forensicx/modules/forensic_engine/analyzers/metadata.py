"""Read-only generic, PDF, and OOXML metadata extraction."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from forensicx.modules.forensic_engine.analyzers.base import BaseAnalyzer
from forensicx.modules.forensic_engine.domain import AnalysisStatus, AnalyzerOutput


class MetadataAnalyzer(BaseAnalyzer):
    """Extract filesystem metadata plus safe PDF and Office document properties."""
    name = "metadata"

    def analyze(self, evidence_path: Path) -> AnalyzerOutput:
        """Extract metadata without trusting or executing document content."""
        stat = evidence_path.stat()
        findings: dict[str, object] = {"filename": evidence_path.name, "extension": evidence_path.suffix.lower(), "size": stat.st_size, "modified_at": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat()}
        if evidence_path.suffix.lower() == ".pdf":
            findings["pdf"] = self._pdf_metadata(evidence_path)
        elif evidence_path.suffix.lower() in {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}:
            findings["office"] = self._office_metadata(evidence_path)
        return AnalyzerOutput(self.name, self.version, AnalysisStatus.SUCCESS, findings)

    @staticmethod
    def _pdf_metadata(path: Path) -> dict[str, str]:
        data = path.read_bytes()[:4 * 1024 * 1024]
        properties: dict[str, str] = {}
        for key in ("Title", "Author", "Subject", "Creator", "Producer", "CreationDate", "ModDate"):
            match = re.search(rb"/" + key.encode() + rb"\s*\(([^)]{0,2048})\)", data)
            if match:
                properties[key.lower()] = match.group(1).decode("latin-1", "replace")
        return properties

    @staticmethod
    def _office_metadata(path: Path) -> dict[str, str]:
        if not zipfile.is_zipfile(path):
            return {"format": "legacy_or_invalid_office_container"}
        with zipfile.ZipFile(path) as archive:
            try:
                root = ET.fromstring(archive.read("docProps/core.xml"))
            except KeyError:
                return {"format": "openxml", "properties": "not_present"}
        values: dict[str, str] = {"format": "openxml"}
        for element in root:
            if element.text:
                values[element.tag.rsplit("}", 1)[-1]] = element.text
        return values
