"""Authentication API routes."""

from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from forensicx.platform.errors import ForensicXError
from forensicx.platform.security import create_access_token


router = APIRouter(tags=["auth"])


class TokenResponse(BaseModel):
    """Access token response DTO."""

    access_token: str = Field(description="Signed JWT access token")
    token_type: str = Field(default="bearer", description="OAuth-compatible token type")
    expires_in: int = Field(description="Token lifetime in seconds")


@router.post("/auth/dev-token", response_model=TokenResponse, summary="Issue a development access token")
async def issue_development_token(request: Request) -> TokenResponse:
    """Issue a local development token for the browser dashboard."""
    settings = request.app.state.settings
    if settings.environment == "production":
        raise ForensicXError("Development token endpoint is disabled in production", 404)
    expires_in = settings.access_token_minutes * 60
    token = create_access_token(
        subject="local-admin",
        roles=["admin", "dashboard:read", "cases:read", "cases:write"],
        secret=settings.jwt_secret,
        expires_in_seconds=expires_in,
    )
    return TokenResponse(access_token=token, expires_in=expires_in)
