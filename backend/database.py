"""Database layer for SOCTriage.

Cases were previously held in memory and lost on every restart. They now
persist to a real database: PostgreSQL in production (via the DATABASE_URL
that Railway injects when a Postgres service is attached) and a local SQLite
file for development when DATABASE_URL is not set.

A triage Case is a deeply nested object -- enrichment results, an incident
report, a timeline. Rather than spreading it across a dozen joined tables,
the queryable scalar fields (status, severity, timestamps) are stored as real
columns and the nested structures are stored as JSON. PostgreSQL and SQLite
both handle JSON natively, so the same code works against either backend.
"""
import os
from datetime import datetime
from pathlib import Path

from sqlalchemy import JSON, DateTime, String, Text, create_engine, inspect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


def _resolve_database_url() -> str:
    """Return the SQLAlchemy URL, defaulting to a local SQLite file."""
    url = os.getenv("DATABASE_URL", "").strip()
    if not url:
        # Local development: no DATABASE_URL set -> use a SQLite file.
        return "sqlite:///./soctriage.db"
    # Railway (like Heroku) hands out the legacy "postgres://" scheme;
    # SQLAlchemy 2.x requires "postgresql://".
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return url


DATABASE_URL = _resolve_database_url()
_IS_SQLITE = DATABASE_URL.startswith("sqlite")

# SQLite needs check_same_thread=False to be usable across the server's threads.
_connect_args = {"check_same_thread": False} if _IS_SQLITE else {}

engine = create_engine(DATABASE_URL, connect_args=_connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class CaseRow(Base):
    """A single triage case.

    Scalar, queryable fields are real columns; the nested enrichment result,
    incident report, and timeline are stored as JSON.
    """

    __tablename__ = "cases"

    case_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    ioc: Mapped[str] = mapped_column(Text)
    ioc_type: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Nested structures, serialized as JSON.
    enrichment: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    report: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    timeline: Mapped[list] = mapped_column(JSON, default=list)


_BACKEND_DIR = Path(__file__).resolve().parent

# The first migration: the schema exactly as create_all() built it before
# Alembic was introduced. See alembic/versions/0001_baseline_cases_table.py.
BASELINE_REVISION = "0001"


def init_db() -> None:
    """Upgrade the database to the newest migration. Safe on every startup.

    The schema is owned by the Alembic migrations in alembic/versions, not by
    Base.metadata.create_all(). Three starting points all end at head:

    - empty database: every migration runs, from the baseline up.
    - database from before migrations existed (it has the `cases` table that
      create_all() made, but no alembic_version table): it already matches the
      baseline, so it is stamped at the baseline and only later migrations run.
      Stamping rather than running the baseline is what keeps its rows intact.
    - migrated database: only migrations it has not yet seen run; at head,
      nothing does.
    """
    # Imported here so that importing database (every module that touches a
    # case does) does not pull in the migration machinery.
    from alembic import command
    from alembic.config import Config

    with engine.begin() as connection:
        config = Config(str(_BACKEND_DIR / "alembic.ini"))
        config.set_main_option("script_location", str(_BACKEND_DIR / "alembic"))
        config.attributes["connection"] = connection

        tables = set(inspect(connection).get_table_names())
        if "cases" in tables and "alembic_version" not in tables:
            command.stamp(config, BASELINE_REVISION)
        command.upgrade(config, "head")
