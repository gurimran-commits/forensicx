"""Database bootstrap and session management for ForensicX."""

from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from forensicx.platform.models import Base
from forensicx.platform.config import Settings
from forensicx.platform import model_registry


LOGGER = logging.getLogger(__name__)


_session_factory: sessionmaker[Session] | None = None


def database_url(database_path: Path) -> str:
    """Build a SQLAlchemy database URL from a local path."""
    database_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{database_path.as_posix()}"


def create_database_engine(settings: Settings) -> Engine:
    """Create a SQLAlchemy engine configured for the active database."""
    engine = create_engine(
        database_url(settings.database_path),
        future=True,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def enable_sqlite_foreign_keys(dbapi_connection: object, connection_record: object) -> None:
        """Enable SQLite foreign-key enforcement for every connection."""
        _ = connection_record
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


def configure_session_factory(settings: Settings) -> sessionmaker[Session]:
    """Configure and return the process-wide SQLAlchemy session factory."""
    global _session_factory
    engine = create_database_engine(settings)
    Base.metadata.create_all(bind=engine)
    _session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
    LOGGER.info("Database initialized at %s", settings.database_path)
    return _session_factory


def session_factory() -> sessionmaker[Session]:
    """Return the configured session factory or fail clearly."""
    if _session_factory is None:
        raise RuntimeError("Database session factory has not been configured")
    return _session_factory


def get_session() -> Session:
    """Create a SQLAlchemy session for non-FastAPI callers and tests."""
    return session_factory()()


def initialize_database(settings: Settings) -> None:
    """Create database objects and configure sessions."""
    configure_session_factory(settings)
