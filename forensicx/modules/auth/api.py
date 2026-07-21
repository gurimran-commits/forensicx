"""Authentication API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from forensicx.modules.auth.models import User
from forensicx.platform.dependencies import database_session
from forensicx.platform.errors import ForensicXError
from forensicx.platform.security import create_access_token, verify_password


router = APIRouter(tags=["auth"])


class TokenResponse(BaseModel):
    """Access token response DTO."""

    access_token: str = Field(description="Signed JWT access token")
    token_type: str = Field(default="bearer", description="OAuth-compatible token type")
    expires_in: int = Field(description="Token lifetime in seconds")


class LoginRequest(BaseModel):
    """Credentials accepted by the local login endpoint."""

    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=72)


@router.post("/auth/login", response_model=TokenResponse, summary="Log in with a local user account")
async def login(credentials: LoginRequest, request: Request, session: Session = Depends(database_session)) -> TokenResponse:
    """Verify credentials and issue a JWT in the standard ForensicX format."""
    user = session.scalar(select(User).where(User.username == credentials.username))
    if user is None or not verify_password(credentials.password, user.hashed_password):
        raise ForensicXError("Invalid username or password", 401)
    expires_in = request.app.state.settings.access_token_minutes * 60
    token = create_access_token(
        subject=user.username,
        roles=user.roles,
        secret=request.app.state.settings.jwt_secret,
        expires_in_seconds=expires_in,
    )
    return TokenResponse(access_token=token, expires_in=expires_in)


@router.post("/auth/dev-token", response_model=TokenResponse, summary="Issue a development access token")
async def issue_development_token(request: Request) -> TokenResponse:
    """Issue a local development token for the browser dashboard."""
    settings = request.app.state.settings
    if settings.environment == "production":
        raise ForensicXError("Development token endpoint is disabled in production", 404)
    expires_in = settings.access_token_minutes * 60
    token = create_access_token(
        subject="local-admin",
        roles=["admin", "dashboard:read", "cases:read", "cases:write", "forensics:read"],
        secret=settings.jwt_secret,
        expires_in_seconds=expires_in,
    )
    return TokenResponse(access_token=token, expires_in=expires_in)
