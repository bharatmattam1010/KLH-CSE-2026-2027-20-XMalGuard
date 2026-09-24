"""Database setup and session management module for XMalGuard.

Provides SQLAlchemy engine, session maker, declarative base,
database initialization, and FastAPI dependency generator.
"""

import logging
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

# Configure SQLite-specific connection arguments if SQLite is used
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """Provide a transactional database session for request handling.

    Yields:
        Session: SQLAlchemy database session.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception as exc:
        logger.error("Database session error: %s", exc, exc_info=True)
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    """Create all database tables defined in the metadata."""
    try:
        logger.info("Initializing database tables...")
        # Import models here to ensure they are registered with Base metadata
        import app.models_db  # noqa: F401
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables initialized successfully.")
    except Exception as exc:
        logger.error("Failed to initialize database tables: %s", exc, exc_info=True)
        raise
