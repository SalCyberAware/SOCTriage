# Database migrations

The backend's schema is owned by [Alembic](https://alembic.sqlalchemy.org/)
migrations in [`backend/alembic/versions/`](../backend/alembic/versions). The
SQLAlchemy models in [`backend/database.py`](../backend/database.py) describe
what the schema *should* be. The migrations are how a real database gets there.

All commands below run from `backend/`.

## How migrations are applied

**Automatically, on every startup.** `database.init_db()`, called from the
FastAPI lifespan in `main.py`, upgrades the database to head before the app
serves a request. A deploy to Railway therefore applies any new migration on
its own. Where the database starts decides what happens:

| Database | What happens |
| --- | --- |
| Empty | Every migration runs, from `0001` up. |
| Created before migrations existed (has `cases`, no `alembic_version`) | Stamped at `0001` without running it, because it already matches that schema. Its rows are kept. Later migrations then run. |
| Already migrated | Only migrations it has not seen run. At head, nothing does. |

**By hand**, using the same URL the app would use. `alembic/env.py` takes it
from `database.DATABASE_URL`: `DATABASE_URL` from the environment or
`backend/.env`, with a local SQLite file when it is unset. Nothing about the
URL is set in `alembic.ini`.

```bash
alembic current              # which revision the database is at
alembic upgrade head         # apply everything outstanding
alembic upgrade head --sql   # print the SQL instead of running it
alembic history              # list migrations
```

Before running any of these, check which database `DATABASE_URL` points at in
your shell and your `.env`.

## Creating a migration

1. Change the model in `backend/database.py`.
2. Bring your local database to head: `alembic upgrade head`.
3. Generate the migration:

   ```bash
   alembic revision --autogenerate -m "add assignee to cases"
   ```

4. **Read the generated file.** Autogenerate is a first draft. It does not
   detect a renamed column or table (it writes a drop and an add, which
   discards the data), and it does not write data migrations. A new
   `NOT NULL` column on a table that already has rows needs a
   `server_default`, or a backfill before the constraint is added.
5. Check both directions run, and that nothing is left over:

   ```bash
   alembic upgrade head
   alembic downgrade -1
   alembic upgrade head
   alembic check                # "No new upgrade operations detected."
   ```

6. Run `pytest`. The suite builds its database from the migrations, so it
   fails if they do not produce the schema the code expects.
7. Commit the model change and the migration together.

SQLite cannot `ALTER` most things in place, so for it `env.py` turns on batch
mode, which rebuilds the table. The same migration then runs on SQLite and
Postgres.

CI runs every migration from an empty Postgres to head, runs `alembic check`,
downgrades to empty and back up, then runs the test suite against that
database (`migrations-postgres` in
[`.github/workflows/backend-tests.yml`](../.github/workflows/backend-tests.yml)).

## Never

- **Never edit a migration that has been applied anywhere else.** Once it has
  merged to `main` it has run in production. Alembic records only the revision
  id, so it will not run the edited version again, and databases silently
  diverge. Fix a mistake with a new migration.
- **Never call `Base.metadata.create_all()` against a real database.** It
  builds tables from the current models with no `alembic_version` row. That
  database then either fails its next upgrade, because the tables already
  exist, or gets stamped at the baseline and has every later migration run
  over tables that already have those changes. It also never alters a table
  that already exists, which is why Alembic replaced it. The only exception is
  a throwaway database in a test that compares against the old schema
  (`tests/test_migrations.py`).
- **Never delete or reorder migrations**, or change a `revision` or
  `down_revision`. Every deployed database's position is recorded against them.
- **Never leave two heads.** If two branches both add a migration, the second
  to merge must rebase it onto the first by changing its `down_revision`
  before it merges. `alembic heads` must print exactly one revision.
- **Never `alembic stamp` a production database** to get past an error. It
  records a schema change that did not happen.
- **Never `downgrade` production without a backup.** Downgrades that drop
  columns drop their data.

## Running more than one process

Migrations run inside application startup, so two processes starting at the
same moment would both try to upgrade. Today the Procfile starts a single
uvicorn process, so this cannot happen. Before scaling to several replicas or
workers, move the upgrade to a one-off release step (`alembic upgrade head`)
or guard it with a Postgres advisory lock.
