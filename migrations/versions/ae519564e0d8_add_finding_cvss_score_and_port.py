"""add finding.cvss_score and finding.port

Revision ID: ae519564e0d8
Revises: 22507e2d8337
Create Date: 2026-09-24 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ae519564e0d8'
down_revision: Union[str, Sequence[str], None] = '22507e2d8337'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('finding') as batch_op:
        batch_op.add_column(sa.Column('cvss_score', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('port', sa.Integer(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('finding') as batch_op:
        batch_op.drop_column('port')
        batch_op.drop_column('cvss_score')
