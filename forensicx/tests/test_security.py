"""Tests for signed access-token creation and validation."""

from __future__ import annotations

import pytest

from forensicx.platform.errors import ForensicXError
from forensicx.platform.security import create_access_token, verify_access_token


def test_access_tokens_verify_and_expired_tokens_are_rejected() -> None:
    """JWTs preserve identity and roles, while expired tokens return a clean error."""
    secret = "test-secret"
    token = create_access_token("analyst", ["cases:read", "evidence:write"], secret, expires_in_seconds=60)

    principal = verify_access_token(token, secret)

    assert principal.subject == "analyst"
    assert principal.roles == frozenset({"cases:read", "evidence:write"})

    expired = create_access_token("analyst", ["cases:read"], secret, expires_in_seconds=-1)
    with pytest.raises(ForensicXError, match="expired") as exc_info:
        verify_access_token(expired, secret)
    assert exc_info.value.status_code == 401
