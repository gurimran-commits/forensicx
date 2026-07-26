"""
Validation service for evidence uploads.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import HTTPException, UploadFile, status


class EvidenceValidator:
    """Validates uploaded evidence before processing."""

    def __init__(self, max_file_size: int, allowed_extensions: tuple[str, ...]) -> None:
        self._max_file_size = max_file_size
        self._allowed_extensions = {extension.lower() for extension in allowed_extensions}

    @staticmethod
    def validate_filename(filename: str) -> None:
        """Validate filename."""

        if not filename:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Filename is required.",
            )

        if ".." in filename:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid filename.",
            )

    def validate_extension(self, filename: str) -> str:
        """Validate file extension."""

        extension = Path(filename).suffix.lower()

        if extension not in self._allowed_extensions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported file type: {extension}",
            )

        return extension

    async def validate_size(self, upload: UploadFile) -> int:
        """
        Validate upload size without loading the
        whole file into memory.
        """

        size = 0

        while chunk := await upload.read(1024 * 1024):
            size += len(chunk)

            if size > self._max_file_size:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail="File exceeds maximum allowed size.",
                )

        await upload.seek(0)

        return size

    async def validate(self, upload: UploadFile) -> int:
        """
        Perform complete validation.

        Returns
        -------
        int
            File size in bytes.
        """

        filename = upload.filename or ""

        self.validate_filename(filename)

        self.validate_extension(filename)

        return await self.validate_size(upload)
