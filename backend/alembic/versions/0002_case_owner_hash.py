"""case owner hash

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-06 12:00:00.000000

Adds cases.owner_hash: the SHA-256 of the session token that opened the case
(see auth.py). Nullable, because every case that exists when this runs was
opened before ownership did, and there is no token to attribute it to. Those
rows keep NULL, which no session token hashes to, so only the API key sees
them afterwards. Nothing is backfilled.

Indexed because every visitor read (list, dashboard) filters on it.

The downgrade drops the index and the column and with them every ownership
record; the cases themselves are untouched. It goes through batch mode so it
also works on SQLite, which cannot drop a column in place on older versions.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '0002'
down_revision: str | Sequence[str] | None = '0001'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('cases', sa.Column('owner_hash', sa.String(length=64), nullable=True))
    op.create_index('ix_cases_owner_hash', 'cases', ['owner_hash'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_cases_owner_hash', table_name='cases')
    with op.batch_alter_table('cases') as batch_op:
        batch_op.drop_column('owner_hash')
