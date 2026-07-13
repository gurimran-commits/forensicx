"""
Secure evidence storage service.
"""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path

from fastapi import UploadFile


class StorageService:
    """Handles secure storage of evidence files."""

    def __init__(self, storage_root: Path) -> None:
        self._storage_root = storage_root

    def create_case_directory(self, case_id: str) -> Path:
        """
        Create the directory structure for a case.

        storage/
            cases/
                <case_id>/
                    evidence/
        """

        directory = (
            self._storage_root
            / "cases"
            / case_id
            / "evidence"
        )

        directory.mkdir(parents=True, exist_ok=True)

        return directory

    def generate_filename(self, extension: str) -> str:
        """
        Generate a collision-resistant filename.
        """

        return f"{uuid.uuid4().hex}{extension.lower()}"

    def save(
        self,
        case_id: str,
        upload: UploadFile,
    ) -> tuple[Path, str]:
        """
        Save uploaded evidence.

        Returns
        -------
        tuple
            (saved_path, generated_filename)
        """

        extension = Path(upload.filename or "").suffix

        filename = self.generate_filename(extension)

        directory = self.create_case_directory(case_id)

        destination = directory / filename

        with destination.open("wb") as buffer:
            shutil.copyfileobj(upload.file, buffer)

        return destination, filename
