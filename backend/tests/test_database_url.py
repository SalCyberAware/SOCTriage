"""Tests for database._resolve_database_url().

The URL must always name the psycopg2 driver. A bare "postgresql://" means
whatever SQLAlchemy's default Postgres driver is, and SQLAlchemy 2.1 changed
that default to psycopg (v3), which is not installed: production crashed on
startup the moment 2.1 was picked up.
"""
import pytest
from sqlalchemy import make_url

import database

_REST = "soctriage@db.example.internal:5432/soctriage"


@pytest.mark.parametrize(
    "raw",
    [
        f"postgres://{_REST}",
        f"postgresql://{_REST}",
        f"postgresql+psycopg2://{_REST}",
    ],
    ids=["legacy-postgres", "bare-postgresql", "already-explicit"],
)
def test_postgres_urls_name_psycopg2_explicitly(raw, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", raw)

    resolved = database._resolve_database_url()

    assert resolved == f"postgresql+psycopg2://{_REST}"
    assert make_url(resolved).get_dialect().driver == "psycopg2"


def test_other_explicit_driver_is_left_alone(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"postgresql+psycopg://{_REST}")

    assert database._resolve_database_url() == f"postgresql+psycopg://{_REST}"


def test_unset_falls_back_to_sqlite(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)

    assert database._resolve_database_url() == "sqlite:///./soctriage.db"
