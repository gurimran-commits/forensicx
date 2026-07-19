"""
Metadata extraction service for evidence files.
"""

from __future__ import annotations

import mimetypes
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass(slots=True)
class FileMetadata:
    """Represents metadata extracted from an evidence file."""

    filename: str
    extension: str
    mime_type: str
    size: int
    created_at: datetime
    modified_at: datetime


class MetadataService:
    """Extract metadata from evidence files."""

    @staticmethod
    def extract(path: Path) -> FileMetadata:
        """
        Extract basic filesystem metadata.

        Parameters
        ----------
        path:
            Path to the stored evidence file.

        Returns
        -------
        FileMetadata
        """

        stats = path.stat()

        mime_type, _ = mimetypes.guess_type(path.name)

        return FileMetadata(
            filename=path.name,
            extension=path.suffix.lower(),
            mime_type=mime_type or "application/octet-stream",
            size=stats.st_size,
            created_at=datetime.fromtimestamp(stats.st_ctime),
            modified_at=datetime.fromtimestamp(stats.st_mtime),
        )
