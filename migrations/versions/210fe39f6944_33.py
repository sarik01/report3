"""33

Revision ID: 210fe39f6944
Revises: 613998a3d8d0
Create Date: 2022-07-18 15:25:35.768842

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '210fe39f6944'
down_revision = '613998a3d8d0'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('_alembic_tmp_order_sign')
    with op.batch_alter_table('order_sign', schema=None) as batch_op:
        batch_op.drop_constraint('fk_order_sign_orders_id_order', type_='foreignkey')
        batch_op.create_foreign_key(batch_op.f('fk_order_sign_orders_id_order'), 'order', ['orders_id'], ['id'], ondelete='CASCADE')

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('phone', sa.String(length=120), nullable=True))
        batch_op.add_column(sa.Column('image', sa.String(length=120), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('image')
        batch_op.drop_column('phone')

    with op.batch_alter_table('order_sign', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('fk_order_sign_orders_id_order'), type_='foreignkey')
        batch_op.create_foreign_key('fk_order_sign_orders_id_order', 'order', ['orders_id'], ['id'])

    op.create_table('_alembic_tmp_order_sign',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('sign', sa.VARCHAR(length=200), nullable=False),
    sa.Column('hash', sa.VARCHAR(length=200), nullable=False),
    sa.Column('order_id', sa.INTEGER(), nullable=True),
    sa.Column('user_id', sa.INTEGER(), nullable=True),
    sa.Column('orders_id', sa.INTEGER(), nullable=True),
    sa.ForeignKeyConstraint(['order_id'], ['report.id'], ),
    sa.ForeignKeyConstraint(['orders_id'], ['order.id'], name='fk_order_sign_orders_id_order', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###
