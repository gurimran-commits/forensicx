"""FastAPI dependency helpers shared across modules."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy.orm import Session

from forensicx.platform.database import get_session


def database_session() -> Generator[Session, None, None]:
    """Yield a SQLAlchemy session for one request."""
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
