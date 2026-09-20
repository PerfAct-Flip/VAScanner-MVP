"""add scan.requested_engines and asset.open_ports

Revision ID: b6ea6af6d45d
Revises: 63330ddb6c77
Create Date: 2026-09-21 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b6ea6af6d45d'
down_revision: Union[str, Sequence[str], None] = '63330ddb6c77'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('scan') as batch_op:
        batch_op.add_column(sa.Column('requested_engines', sa.String(length=100), nullable=True))
    with op.batch_alter_table('asset') as batch_op:
        batch_op.add_column(sa.Column('open_ports', sa.String(length=255), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('asset') as batch_op:
        batch_op.drop_column('open_ports')
    with op.batch_alter_table('scan') as batch_op:
        batch_op.drop_column('requested_engines')
