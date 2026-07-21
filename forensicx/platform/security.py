"""Authentication and authorization helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext

from forensicx.platform.errors import ForensicXError


bearer_scheme = HTTPBearer(auto_error=False)
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__truncate_error=True)


@dataclass(frozen=True)
class Principal:
    """Authenticated user identity."""

    subject: str
    roles: frozenset[str]


def hash_password(password: str) -> str:
    """Hash a user password with bcrypt for persistent storage."""
    return password_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """Safely verify a plaintext password against its bcrypt hash."""
    try:
        return password_context.verify(password, hashed_password)
    except (TypeError, ValueError):
        return False


def _b64url(data: bytes) -> str:
    """Base64-url encode bytes without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    """Decode an unpadded base64-url string."""
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def create_access_token(subject: str, roles: list[str], secret: str, expires_in_seconds: int) -> str:
    """Create a signed HS256 JWT access token."""
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": subject, "roles": roles, "iat": now, "exp": now + expires_in_seconds}
    signing_input = f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}.{_b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    signature = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url(signature)}"


def verify_access_token(token: str, secret: str) -> Principal:
    """Validate a signed JWT access token and return its principal."""
    try:
        header_part, payload_part, signature_part = token.split(".")
        signing_input = f"{header_part}.{payload_part}"
        expected = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url(expected), signature_part):
            raise ForensicXError("Invalid access token", 401)
        header = json.loads(_b64url_decode(header_part))
        payload: dict[str, Any] = json.loads(_b64url_decode(payload_part))
        if header.get("alg") != "HS256":
            raise ForensicXError("Unsupported token algorithm", 401)
        if int(payload.get("exp", 0)) < int(time.time()):
            raise ForensicXError("Access token expired", 401)
        subject = str(payload.get("sub", ""))
        roles = payload.get("roles", [])
        if not subject or not isinstance(roles, list):
            raise ForensicXError("Invalid token claims", 401)
        return Principal(subject=subject, roles=frozenset(str(role) for role in roles))
    except ForensicXError:
        raise
    except Exception as exc:
        raise ForensicXError("Invalid access token", 401) from exc


async def current_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> Principal:
    """Resolve the authenticated principal from the bearer token."""
    if credentials is None:
        raise ForensicXError("Authentication required", 401)
    return verify_access_token(credentials.credentials, request.app.state.settings.jwt_secret)


def require_role(required_role: str):
    """Create a dependency that enforces a required RBAC role."""

    async def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        """Authorize the principal against the required role."""
        if required_role not in principal.roles and "admin" not in principal.roles:
            raise ForensicXError("Insufficient permissions", 403)
        return principal

    return dependency
