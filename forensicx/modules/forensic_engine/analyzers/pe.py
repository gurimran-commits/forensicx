"""Portable Executable header and import-table inspection."""
from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path

from forensicx.modules.forensic_engine.analyzers.base import BaseAnalyzer
from forensicx.modules.forensic_engine.domain import AnalysisStatus, AnalyzerOutput


class PEAnalyzer(BaseAnalyzer):
    """Parse PE headers and imported DLL names without loading or executing code."""
    name = "pe"

    def analyze(self, evidence_path: Path) -> AnalyzerOutput:
        """Inspect a bounded binary buffer for PE machine, timestamp, and imports."""
        data = evidence_path.read_bytes()[:32 * 1024 * 1024]
        if len(data) < 64 or data[:2] != b"MZ":
            return self.skipped("not_a_pe_file")
        offset = struct.unpack_from("<I", data, 0x3C)[0]
        if offset + 24 > len(data) or data[offset:offset + 4] != b"PE\0\0":
            return AnalyzerOutput(self.name, self.version, AnalysisStatus.FAILED, {}, "Invalid PE signature")
        machine, sections, timestamp, _, _, optional_size, _ = struct.unpack_from("<HHIIIHH", data, offset + 4)
        optional = offset + 24
        magic = struct.unpack_from("<H", data, optional)[0]
        directory_offset = optional + (112 if magic == 0x20B else 96)
        imports: list[str] = []
        if directory_offset + 16 <= len(data):
            import_rva, _ = struct.unpack_from("<II", data, directory_offset + 8)
            section_offset = optional + optional_size
            section_rows = [struct.unpack_from("<8sIIIIIIHHI", data, section_offset + index * 40) for index in range(sections) if section_offset + (index + 1) * 40 <= len(data)]
            import_offset = self._rva_to_offset(import_rva, section_rows)
            if import_offset is not None:
                for index in range(256):
                    row = import_offset + index * 20
                    if row + 20 > len(data): break
                    _, _, _, name_rva, _ = struct.unpack_from("<IIIII", data, row)
                    if not name_rva: break
                    name_offset = self._rva_to_offset(name_rva, section_rows)
                    if name_offset is not None:
                        end = data.find(b"\0", name_offset, min(name_offset + 512, len(data)))
                        if end != -1: imports.append(data[name_offset:end].decode("ascii", "replace"))
        return AnalyzerOutput(self.name, self.version, AnalysisStatus.SUCCESS, {"machine": hex(machine), "section_count": sections, "compile_timestamp": datetime.fromtimestamp(timestamp, UTC).isoformat(), "imported_dlls": imports})

    @staticmethod
    def _rva_to_offset(rva: int, sections: list[tuple[object, ...]]) -> int | None:
        for row in sections:
            virtual_size, virtual_address, raw_size, raw_offset = row[1], row[2], row[3], row[4]
            if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
                return raw_offset + rva - virtual_address
        return None
