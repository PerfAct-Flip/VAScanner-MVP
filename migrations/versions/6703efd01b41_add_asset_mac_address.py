"""add asset mac_address

Revision ID: 6703efd01b41
Revises: cc60986f55f2
Create Date: 2026-09-18 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6703efd01b41'
down_revision: Union[str, Sequence[str], None] = 'cc60986f55f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('asset') as batch_op:
        batch_op.add_column(sa.Column('mac_address', sa.String(length=17), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('asset') as batch_op:
        batch_op.drop_column('mac_address')
