"""
Validation service for evidence uploads.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import HTTPException, UploadFile, status


class EvidenceValidator:
    """Validates uploaded evidence before processing."""

    # Maximum upload size (500 MB)
    MAX_FILE_SIZE = 500 * 1024 * 1024

    # Allowed extensions
    ALLOWED_EXTENSIONS = {
        ".zip",
        ".7z",
        ".rar",
        ".pcap",
        ".pcapng",
        ".img",
        ".iso",
        ".e01",
        ".raw",
        ".mem",
        ".dmp",
        ".bin",
        ".exe",
        ".dll",
        ".pdf",
        ".docx",
        ".xlsx",
        ".csv",
        ".json",
        ".xml",
        ".txt",
        ".jpg",
        ".jpeg",
        ".png",
    }

    @classmethod
    def validate_filename(cls, filename: str) -> None:
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

    @classmethod
    def validate_extension(cls, filename: str) -> str:
        """Validate file extension."""

        extension = Path(filename).suffix.lower()

        if extension not in cls.ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported file type: {extension}",
            )

        return extension

    @classmethod
    async def validate_size(cls, upload: UploadFile) -> int:
        """
        Validate upload size without loading the
        whole file into memory.
        """

        size = 0

        while chunk := await upload.read(1024 * 1024):
            size += len(chunk)

            if size > cls.MAX_FILE_SIZE:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail="File exceeds maximum allowed size.",
                )

        await upload.seek(0)

        return size

    @classmethod
    async def validate(cls, upload: UploadFile) -> int:
        """
        Perform complete validation.

        Returns
        -------
        int
            File size in bytes.
        """

        filename = upload.filename or ""

        cls.validate_filename(filename)

        cls.validate_extension(filename)

        return await cls.validate_size(upload)
