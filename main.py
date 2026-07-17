"""FastAPI application factory for ForensicX."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from forensicx.modules.chain_of_custody.api import router as custody_router

from forensicx.modules.auth.api import router as auth_router
from forensicx.modules.cases.api import router as cases_router
from forensicx.modules.dashboard.api import router as dashboard_router
from forensicx.modules.evidence.api import router as evidence_router
from forensicx.platform.config import Settings, get_settings
from forensicx.platform.database import initialize_database
from forensicx.platform.errors import register_exception_handlers
from forensicx.platform.middleware import RequestLoggingMiddleware


LOGGER = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the ForensicX FastAPI application."""
    active_settings = settings or get_settings()
    logging.basicConfig(level=active_settings.log_level)
    initialize_database(active_settings)

    app = FastAPI(
        title="ForensicX API",
        version="0.1.0",
        description="REST API for the ForensicX digital forensics dashboard module.",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )
    app.state.settings = active_settings
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=active_settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    )
    register_exception_handlers(app)
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(dashboard_router, prefix="/api/v1")
    app.include_router(cases_router, prefix="/api/v1")
    app.include_router(evidence_router, prefix="/api/v1")
    app.include_router(custody_router, prefix="/api/v1")

    @app.get("/", include_in_schema=False)
    async def dashboard_page() -> FileResponse:
        """Serve the ForensicX dashboard shell."""
        dashboard_path = Path(__file__).resolve().parent.parent / "outputs" / "forensicx-dashboard.html"
        return FileResponse(dashboard_path)

    @app.get("/dashboard", include_in_schema=False)
    async def dashboard_alias() -> FileResponse:
        """Serve the dashboard shell from a named route."""
        dashboard_path = Path(__file__).resolve().parent.parent / "outputs" / "forensicx-dashboard.html"
        return FileResponse(dashboard_path)

    LOGGER.info("ForensicX API configured with database %s", active_settings.database_path)
    return app


app = create_app()
