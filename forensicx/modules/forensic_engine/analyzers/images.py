"""Image dimension and JPEG EXIF inspection."""
from __future__ import annotations

import struct
from pathlib import Path

from forensicx.modules.forensic_engine.analyzers.base import BaseAnalyzer
from forensicx.modules.forensic_engine.domain import AnalysisStatus, AnalyzerOutput


class ImageAnalyzer(BaseAnalyzer):
    """Read basic PNG/JPEG dimensions and report whether JPEG EXIF is present."""
    name = "images"

    def analyze(self, evidence_path: Path) -> AnalyzerOutput:
        """Perform bounded, non-decoding image inspection."""
        data = evidence_path.read_bytes()[:128 * 1024]
        if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 24:
            width, height = struct.unpack(">II", data[16:24])
            return AnalyzerOutput(self.name, self.version, AnalysisStatus.SUCCESS, {"format": "png", "width": width, "height": height, "exif_present": b"eXIf" in data})
        if data.startswith(b"\xff\xd8"):
            exif = self._jpeg_exif(data)
            return AnalyzerOutput(self.name, self.version, AnalysisStatus.SUCCESS, {"format": "jpeg", "exif_present": bool(exif), "exif": exif, "xmp_present": b"http://ns.adobe.com/xap/1.0/" in data})
        return self.skipped("not_a_supported_image")

    @staticmethod
    def _jpeg_exif(data: bytes) -> dict[str, object]:
        """Extract a small allow-listed set of TIFF EXIF values from JPEG APP1."""
        start = data.find(b"Exif\0\0")
        if start < 0 or start + 14 > len(data):
            return {}
        tiff = data[start + 6:]
        order = tiff[:2]
        if order not in {b"II", b"MM"}:
            return {}
        endian = "<" if order == b"II" else ">"
        try:
            offset = struct.unpack_from(endian + "I", tiff, 4)[0]
            count = struct.unpack_from(endian + "H", tiff, offset)[0]
        except struct.error:
            return {}
        tags = {0x010F: "make", 0x0110: "model", 0x0112: "orientation", 0x0132: "modified_at"}
        result: dict[str, object] = {}
        for index in range(min(count, 64)):
            position = offset + 2 + index * 12
            try:
                tag, kind, length, value = struct.unpack_from(endian + "HHII", tiff, position)
            except struct.error:
                break
            if tag not in tags:
                continue
            if kind == 2:  # ASCII
                raw = tiff[value:value + min(length, 1024)] if length > 4 else struct.pack(endian + "I", value)[:length]
                result[tags[tag]] = raw.rstrip(b"\0").decode("latin-1", "replace")
            elif kind == 3 and length == 1:
                result[tags[tag]] = value & 0xFFFF if endian == "<" else value >> 16
        return result
