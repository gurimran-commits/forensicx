"""MIME, extension, and file-signature verification."""
from __future__ import annotations

import mimetypes
from pathlib import Path

from forensicx.modules.forensic_engine.analyzers.base import BaseAnalyzer
from forensicx.modules.forensic_engine.domain import AnalysisStatus, AnalyzerOutput


_SIGNATURES = (
    (b"%PDF-", "pdf", "application/pdf", {".pdf"}),
    (b"PK\x03\x04", "zip", "application/zip", {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".odt"}),
    (b"Rar!\x1a\x07", "rar", "application/vnd.rar", {".rar"}),
    (b"7z\xbc\xaf\x27\x1c", "7z", "application/x-7z-compressed", {".7z"}),
    (b"MZ", "pe", "application/vnd.microsoft.portable-executable", {".exe", ".dll", ".sys"}),
    (b"\x89PNG\r\n\x1a\n", "png", "image/png", {".png"}),
    (b"\xff\xd8\xff", "jpeg", "image/jpeg", {".jpg", ".jpeg"}),
    (b"GIF87a", "gif", "image/gif", {".gif"}),
    (b"GIF89a", "gif", "image/gif", {".gif"}),
)


class MagicAnalyzer(BaseAnalyzer):
    """Validate claimed extension/MIME data against safe magic-byte signatures."""
    name = "magic"

    def analyze(self, evidence_path: Path) -> AnalyzerOutput:
        """Read a small header and report signature/extension consistency."""
        header = evidence_path.read_bytes()[:32]
        extension = evidence_path.suffix.lower()
        guessed_mime = mimetypes.guess_type(evidence_path.name)[0] or "application/octet-stream"
        detected = next((item for item in _SIGNATURES if header.startswith(item[0])), None)
        if detected is None:
            findings = {"extension": extension, "declared_mime": guessed_mime, "detected_type": "unknown", "mime_valid": None, "extension_matches": None}
        else:
            _, detected_type, detected_mime, extensions = detected
            findings = {"extension": extension, "declared_mime": guessed_mime, "detected_type": detected_type, "detected_mime": detected_mime, "mime_valid": guessed_mime in {detected_mime, "application/octet-stream"}, "extension_matches": extension in extensions}
        return AnalyzerOutput(self.name, self.version, AnalysisStatus.SUCCESS, findings)
