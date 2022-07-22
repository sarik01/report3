import json

from flask import Blueprint, request, jsonify
from flask_login import current_user, login_required
from werkzeug.exceptions import abort

from report import db, ma
from report.user.routes import admin_permission, staff_permission

from report.models import Report, User, Order, OrderSign

tasks = Blueprint('tasks', __name__)


class Schema(ma.Schema):
    class Meta:
        fields = ('id', 'task',
                  'term_execution',
                  'executed',
                  'status',
                  'user_id',

                  'user_file',
                  'user_url',
                  'from_last_name',
                  'from_first_name',
                  'from_role'
                  'content'
                  'image'
                  )


schema = Schema()
schemas = Schema(many=True)


@tasks.route('/add_task', methods=['POST'])
@login_required
@admin_permission.require(http_exception=403)
def addTask():
    id = request.args.get('id')
    user = User.query.filter_by(id=id).first()
    if request.method == 'POST':
        report = Report(task=request.form.get('task'), term_execution=request.form.get('term_execution'),
                        executed=request.form.get('executed'), status=request.form.get('status'),
                        user_id=user.id, from_last_name=current_user.last_name, from_first_name=current_user.first_name,
                        from_role=current_user.roles, from_id=current_user.id)

        db.session.add(report)
        db.session.commit()

        return jsonify({'msg': 'task added!'})


@tasks.route('/update_task', methods=['POST'])
@login_required
# @admin_permission.require(http_exception=403)
def updateTask():
    id = request.args.get('id')

    if request.method == 'POST':
        report = Report.query.get(id)

        report.task = request.form.get('task')
        report.term_execution = request.form.get('term_execution')
        report.executed = request.form.get('executed')
        report.status = request.form.get('status')

        try:
            db.session.commit()
            return jsonify({'msg': 'task updated!'})
        except:
            return jsonify({'msg': 'Wrong!'})


@tasks.route('/delete_task')
@login_required
@admin_permission.require(http_exception=403)
def deleteTask():
    id = request.args.get('id')
    report = Report.query.get_or_404(id)

    if report.from_id != current_user.id:
        abort(403)

    try:
        db.session.delete(report)
        db.session.commit()
        return jsonify({'msg': 'task deleted!'})
    except:
        return jsonify({'msg': 'Wrong!'})


@tasks.route('/admin/get_task')
@login_required
@admin_permission.require(http_exception=403)
def AdmingetTask():
    id = request.args.get('id')
    report = Report.query.get_or_404(id)

    return schema.jsonify(report)


@tasks.route('/get/all/tasks')
@login_required
@admin_permission.require(http_exception=403)
def allTasks():
    return jsonify([x.format() for x in Report.query.all()])


@tasks.route('/my_tasks')
@login_required
# @staff_permission.require(http_exception=403)
def myTasks():
    tasks = Report.query.filter_by(user_id=current_user.id)

    return schemas.dumps([x.format() for x in tasks], ensure_ascii=False).encode('utf-8')


@tasks.route('/send/on_sign', methods=['POST', 'GET'])
@login_required
def SendonSign():
    if request.method == 'POST':

        order = Order(user_id=current_user.id)

        db.session.add(order)
        db.session.commit()
        if order:

            task = Report.query.filter_by(status='status', user_id=current_user.id)

            for i in task:
                i.status = 'sent'

                db.session.commit()

            return jsonify({'msg': 'Sent!'})


@tasks.route('/sign_order', methods=['POST', 'GET'])
@login_required
def signOrder():
    id = request.args.get('id')
    order = Order.query.get(id)

    if request.method == 'POST':
        order_sign = OrderSign(user_id=current_user.id, sign=request.form.get('sign'), hash=request.form.get('hash'),
                               orders_id=order.id)

        db.session.add(order_sign)
        db.session.commit()

        return jsonify({'msg': 'signed!'})


@tasks.route('/all/user/order')
@login_required
def orders():
    if current_user.id == 1:
        order = Order.query.filter_by(status='new').all()

        return jsonify([x.format() for x in order])
        # return schema.jsonify(order)
        # return schemas.dumps(order)

    if current_user.id == 11:
        order = Order.query.filter_by(status='step1').all()

        print(order)
        return jsonify([x.format() for x in order])

    abort(403)


@tasks.route('/change_status', methods=['POST', 'GET'])
@login_required
def changeStatus():
    id = request.args.get('id')
    order = Order.query.get(id)

    if request.method == 'POST':

        order.status = request.form.get('status')

        db.session.commit()

        if current_user.id == 1:
            task = Report.query.filter_by(status='sent', user_id=order.user_id, )

            for i in task:
                i.status = 'checked'

                db.session.commit()
                print(i.user_id)

        return jsonify({'msg': 'changed'})
    return schema.jsonify(order)


@tasks.route('/my_sent_orders')
@login_required
def mySentOrders():
    orders = Order.query.filter_by(user_id=current_user.id)

    return jsonify([x.format() for x in orders])
