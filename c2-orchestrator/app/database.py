# ============================================================================
# FuzzStrike C2 Orchestrator — Database Session Management
# ============================================================================
# Provides SQLAlchemy engine, session factory, and dependency injection
# for FastAPI route handlers. Uses SQLite with WAL mode for concurrent
# read performance while maintaining write safety.
#
# Architecture Note:
#   We use synchronous SQLAlchemy here (not async) because SQLite has
#   inherent write serialization. The async overhead adds complexity
#   without meaningful throughput gains for our write-heavy workload.
#   FastAPI handles concurrency at the ASGI layer regardless.
# ============================================================================

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker, DeclarativeBase

from app.config import get_settings


# ── Declarative Base ──────────────────────────────────────────────────────
# All ORM models inherit from this base class.
class Base(DeclarativeBase):
    """
    SQLAlchemy declarative base for all FuzzStrike ORM models.
    Using the modern DeclarativeBase (SQLAlchemy 2.0 style) instead
    of the legacy declarative_base() factory.
    """
    pass


def _create_engine():
    """
    Create and configure the SQLAlchemy engine.

    Configuration choices:
      - check_same_thread=False: Required for SQLite with FastAPI's
        thread pool executor. Safe because we use scoped sessions.
      - pool_pre_ping=True: Validates connections before use, preventing
        stale connection errors after SQLite file changes.

    Returns:
        Engine: Configured SQLAlchemy engine instance.
    """
    settings = get_settings()
    database_url = f"sqlite:///{settings.db_path}"

    engine = create_engine(
        database_url,
        # SQLite requires this for multi-threaded access
        connect_args={"check_same_thread": False},
        # Validate connections before checkout from pool
        pool_pre_ping=True,
        # Echo SQL statements in development mode
        echo=(settings.env == "development"),
    )

    # ── Enable WAL mode for better concurrent read performance ─────────
    # WAL (Write-Ahead Logging) allows readers to not block writers
    # and vice versa. Critical for a system where telemetry writes
    # happen concurrently with dashboard reads.
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        # WAL mode: concurrent readers, single writer
        cursor.execute("PRAGMA journal_mode=WAL")
        # Foreign key enforcement (SQLite has this OFF by default!)
        cursor.execute("PRAGMA foreign_keys=ON")
        # Synchronous NORMAL: good balance of safety and speed
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

    return engine


# ── Module-level engine and session factory ───────────────────────────────
engine = _create_engine()

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def init_db() -> None:
    """
    Initialize the database schema.

    Creates all tables defined by ORM models that inherit from Base.
    This is idempotent — calling it multiple times is safe.
    Called once at application startup in main.py.
    """
    Base.metadata.create_all(bind=engine)


def get_db() -> Session:
    """
    FastAPI dependency that provides a database session.

    Usage in route handlers:
        @router.get("/items")
        def get_items(db: Session = Depends(get_db)):
            ...

    The session is automatically closed after the request completes,
    even if an exception occurs (finally block guarantees cleanup).

    Yields:
        Session: A SQLAlchemy session scoped to the current request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
