"""add identity_confidence and scan_engine_target

Revision ID: 63330ddb6c77
Revises: 6703efd01b41
Create Date: 2026-09-18 00:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '63330ddb6c77'
down_revision: Union[str, Sequence[str], None] = '6703efd01b41'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('asset') as batch_op:
        batch_op.add_column(sa.Column('identity_confidence', sa.String(length=20), nullable=True))

    op.create_table('scan_engine_target',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('scan_engine_id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['scan_engine_id'], ['scan_engine.id'], ),
    sa.ForeignKeyConstraint(['asset_id'], ['asset.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('scan_engine_id', 'asset_id', name='uq_scan_engine_target')
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('scan_engine_target')
    with op.batch_alter_table('asset') as batch_op:
        batch_op.drop_column('identity_confidence')
