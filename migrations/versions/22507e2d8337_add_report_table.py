"""add report table

Revision ID: 22507e2d8337
Revises: b6ea6af6d45d
Create Date: 2026-09-23 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '22507e2d8337'
down_revision: Union[str, Sequence[str], None] = 'b6ea6af6d45d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('report',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('scan_id', sa.Integer(), nullable=True),
    sa.Column('format', sa.String(length=10), nullable=False),
    sa.Column('content', sa.LargeBinary(), nullable=False),
    sa.Column('finding_count', sa.Integer(), nullable=False),
    sa.Column('generated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['scan_id'], ['scan.id'], ),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('report')
