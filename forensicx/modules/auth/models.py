"""Persistent authentication models."""

from __future__ import annotations

from sqlalchemy import JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from forensicx.platform.models import Base


class User(Base):
    """A local user account that can authenticate to the API."""

    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(120), primary_key=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    roles: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
