"""Tests for database.init_db(), which owns the schema through Alembic.

Each test points init_db at its own SQLite file (tmp_path), away from the
shared test database, so it can start from a precise state: empty, built by the
old create_all() startup, or already migrated.
"""
import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text

import database
from database import BASELINE_REVISION, Base


@pytest.fixture
def db_engine(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{(tmp_path / 'migrate.db').as_posix()}")
    monkeypatch.setattr(database, "engine", engine)
    yield engine
    engine.dispose()


def _head() -> str:
    config = Config(str(database._BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(database._BACKEND_DIR / "alembic"))
    head = ScriptDirectory.from_config(config).get_current_head()
    assert head is not None
    return head


def _version(engine) -> str:
    with engine.connect() as connection:
        return connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()


def _schema(engine) -> dict:
    """Every column and index of every application table, comparably."""
    inspector = inspect(engine)
    return {
        table: {
            "columns": [
                (c["name"], str(c["type"]), c["nullable"]) for c in inspector.get_columns(table)
            ],
            "pk": inspector.get_pk_constraint(table)["constrained_columns"],
            "indexes": sorted(
                (i["name"], tuple(i["column_names"]), bool(i["unique"])) for i in inspector.get_indexes(table)
            ),
        }
        for table in sorted(inspector.get_table_names())
        if table != "alembic_version"
    }


def test_empty_database_is_migrated_to_head(db_engine):
    database.init_db()

    assert _version(db_engine) == _head()
    assert "cases" in inspect(db_engine).get_table_names()


def test_migrated_schema_matches_what_create_all_built(db_engine, tmp_path):
    """The baseline must reproduce the pre-Alembic schema exactly."""
    legacy = create_engine(f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}")
    Base.metadata.create_all(bind=legacy)

    database.init_db()

    assert _schema(db_engine) == _schema(legacy)
    legacy.dispose()


def test_pre_migration_database_is_stamped_and_keeps_its_rows(db_engine):
    """A database the old startup built is adopted, not rebuilt."""
    Base.metadata.create_all(bind=db_engine)
    with db_engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO cases (case_id, ioc, ioc_type, status, severity, created_at, updated_at, timeline) "
            "VALUES ('CASE-1', '8.8.8.8', 'ip', 'open', 'low', '2026-01-01', '2026-01-01', '[]')"
        ))

    database.init_db()

    assert _version(db_engine) == _head()
    with db_engine.connect() as connection:
        assert connection.execute(text("SELECT case_id FROM cases")).scalars().all() == ["CASE-1"]


def test_init_db_is_idempotent(db_engine):
    database.init_db()
    database.init_db()

    assert _version(db_engine) == _head()


def test_baseline_is_the_root_revision():
    config = Config(str(database._BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(database._BACKEND_DIR / "alembic"))
    base = ScriptDirectory.from_config(config).get_bases()

    assert base == [BASELINE_REVISION]
