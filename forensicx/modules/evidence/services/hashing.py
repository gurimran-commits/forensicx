"""
Cryptographic hash calculation utilities.

This module computes hashes using streaming reads so very large
evidence files (disk images, memory dumps, PCAPs) can be processed
without loading the entire file into memory.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO


CHUNK_SIZE = 1024 * 1024  # 1 MB


class HashingService:
    """Provides cryptographic hashing for evidence files."""

    @staticmethod
    def _calculate(file: BinaryIO) -> tuple[str, str, str]:
        """
        Calculate MD5, SHA1 and SHA256 from a file object.

        Parameters
        ----------
        file:
            Binary file opened in 'rb' mode.

        Returns
        -------
        tuple
            (md5, sha1, sha256)
        """

        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        while chunk := file.read(CHUNK_SIZE):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

        return (
            md5.hexdigest(),
            sha1.hexdigest(),
            sha256.hexdigest(),
        )

    @classmethod
    def from_path(cls, path: Path) -> tuple[str, str, str]:
        """
        Calculate hashes from a filesystem path.
        """

        with path.open("rb") as file:
            return cls._calculate(file)
