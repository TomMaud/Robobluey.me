"""Adding User Table

Revision ID: a73ecc82439e
Revises: 2916aa09a4a9
Create Date: 2024-10-19 15:06:11.077522

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a73ecc82439e'
down_revision = '2916aa09a4a9'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('mfakey', sa.String(length=32), nullable=False))
        batch_op.add_column(sa.Column('mfaenables', sa.Boolean(), nullable=False))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('mfaenables')
        batch_op.drop_column('mfakey')

    # ### end Alembic commands ###
