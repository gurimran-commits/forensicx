"""Text-content forensic analyzer."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from pathlib import Path

from forensicx.modules.forensic_engine.analyzers.base import BaseAnalyzer
from forensicx.modules.forensic_engine.domain import AnalysisStatus, AnalyzerOutput


class TextAnalyzer(BaseAnalyzer):
    """Extract basic forensic indicators from readable text files."""

    name = "text"
    version = "1.0"

    SUPPORTED_EXTENSIONS = {
        ".txt",
        ".log",
        ".csv",
        ".json",
        ".xml",
        ".html",
        ".htm",
        ".md",
        ".yaml",
        ".yml",
        ".ini",
        ".conf",
    }

    MAX_READ_SIZE = 10 * 1024 * 1024

    def analyze(self, path: Path) -> AnalyzerOutput:
        """Analyze a text file and extract basic indicators."""

        if path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
            return AnalyzerOutput(
                self.name,
                self.version,
                AnalysisStatus.SKIPPED,
                {"reason": "not_a_supported_text_file"},
                None,
            )

        try:
            if path.stat().st_size > self.MAX_READ_SIZE:
                return AnalyzerOutput(
                    self.name,
                    self.version,
                    AnalysisStatus.SKIPPED,
                    {"reason": "file_too_large"},
                    None,
                )

            content = path.read_text(
                encoding="utf-8",
                errors="replace",
            )

            findings = {
                "encoding": "utf-8",
                "size": len(content),
                "line_count": len(content.splitlines()),
                "sha256": hashlib.sha256(
                    content.encode("utf-8")
                ).hexdigest(),
                "ipv4": self._extract_ipv4(content),
                "urls": self._extract_urls(content),
                "domains": self._extract_domains(content),
                "emails": self._extract_emails(content),
                "sha256_hashes": self._extract_sha256_hashes(content),
            }

            return AnalyzerOutput(
                self.name,
                self.version,
                AnalysisStatus.SUCCESS,
                findings,
                None,
            )

        except Exception:
            return AnalyzerOutput(
                self.name,
                self.version,
                AnalysisStatus.FAILED,
                {},
                "Text analysis failed",
            )

    @staticmethod
    def _extract_ipv4(content: str) -> list[str]:
        """Extract valid IPv4 addresses."""

        candidates = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            content,
        )

        results = []

        for value in candidates:
            try:
                ipaddress.IPv4Address(value)
                results.append(value)
            except ValueError:
                continue

        return sorted(set(results))

    @staticmethod
    def _extract_urls(content: str) -> list[str]:
        """Extract HTTP and HTTPS URLs."""

        values = re.findall(
            r"https?://[^\s\"'<>]+",
            content,
            flags=re.IGNORECASE,
        )

        return sorted(set(values))

    @staticmethod
    def _extract_domains(content: str) -> list[str]:
        """Extract simple domain names."""

        values = re.findall(
            r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
            content,
        )

        return sorted(set(values))

    @staticmethod
    def _extract_emails(content: str) -> list[str]:
        """Extract email addresses."""

        values = re.findall(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            content,
        )

        return sorted(set(values))

    @staticmethod
    def _extract_sha256_hashes(content: str) -> list[str]:
        """Extract SHA-256 hexadecimal hashes."""

        values = re.findall(
            r"\b[a-fA-F0-9]{64}\b",
            content,
        )

        return sorted(set(value.lower() for value in values))
