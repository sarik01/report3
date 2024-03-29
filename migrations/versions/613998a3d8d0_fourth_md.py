"""fourth md

Revision ID: 613998a3d8d0
Revises: ac9c61baa3ff
Create Date: 2022-07-09 09:27:46.222566

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '613998a3d8d0'
down_revision = 'ac9c61baa3ff'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('report', schema=None) as batch_op:
        batch_op.add_column(sa.Column('order_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key(batch_op.f('fk_report_order_id_order'), 'order', ['order_id'], ['id'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('report', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('fk_report_order_id_order'), type_='foreignkey')
        batch_op.drop_column('order_id')

    # ### end Alembic commands ###
