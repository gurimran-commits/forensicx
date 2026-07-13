"""HTTP exception handling for ForensicX."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


LOGGER = logging.getLogger(__name__)


class ForensicXError(Exception):
    """Base exception for expected application failures."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        """Create an application error with an HTTP status code."""
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def register_exception_handlers(app: FastAPI) -> None:
    """Register JSON exception handlers on the FastAPI app."""

    @app.exception_handler(ForensicXError)
    async def forensicx_error_handler(request: Request, exc: ForensicXError) -> JSONResponse:
        """Return structured JSON for expected application errors."""
        LOGGER.warning("Application error at %s: %s", request.url.path, exc.message)
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        """Return structured JSON for unexpected server errors."""
        LOGGER.exception("Unhandled error at %s", request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})
