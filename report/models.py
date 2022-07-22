import json
from datetime import datetime
from flask import current_app
from report import db
import jwt
from flask_login import UserMixin, current_user


class JsonEcodeDict(db.TypeDecorator):
    impl = db.Text

    def process_bind_param(self, value, dialect):
        if value is None:
            return '[]'
        else:
            return json.dumps(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return []
        else:
            return json.loads(value)


class Sections(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    section = db.Column(db.String(200), nullable=False, unique=True)

    def format(self):
        return {
            'id': self.id,
            'section': self.section
        }

    def __repr__(self):
        return self.section + " id: " + str(self.id)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    first_name = db.Column(db.String(120), nullable=False)
    last_name = db.Column(db.String(120), nullable=False)
    roles = db.Column(db.String(120), default='user', nullable=False)
    region = db.Column(db.String(120), nullable=False)
    section_id = db.Column(db.Integer, db.ForeignKey('sections.id'))
    section = db.relationship('Sections', backref=db.backref('user_section', lazy=True, cascade="all, delete-orphan"))
    order_signs = db.relationship('OrderSign', backref='signed_by', lazy=True, cascade="all, delete-orphan")
    order = db.relationship('Order', backref='ordered', lazy=True, cascade="all, delete-orphan")
    phone = db.Column(db.String(120))
    image = db.Column(db.String(120), default='56c4c40d8df84ab45646d19add33d652.jpg')
    phones = db.Column(JsonEcodeDict)

    report_user = db.relationship('Report', backref='reporter', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return self.last_name + ' ' + self.first_name

    def getToken(self):
        token = jwt.encode({'user_id': self.id,
                            }, current_app.config['SECRET_KEY'],
                           algorithm='HS256')
        return token

    @staticmethod
    def verify_token(token):
        try:
            view_token = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms='HS256')
            user_id = view_token['user_id']

        except:
            return None
        return User.query.get(user_id)

    def format(self):

        count = 0
        for x in self.report_user:
            x

            count += 1


        counter = 0
        for i in Report.query.filter_by(status='checked', user_id=self.id):
            i
            counter += 1

        counter1 = 0
        if Report.query.filter_by(status='sent', user_id=self.id):
            for i in Report.query.filter_by(status='sent', user_id=self.id):
                i
                counter1 += 1

        for i in Report.query.filter_by(status='status', user_id=self.id):
            i
            counter1 += 1

        return {
            'id': self.id,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'role': self.roles,
            'region': self.region,
            'section': [x.format() for x in Sections.query.filter_by(id=self.section_id)],
            'tasks': count,
            'done_tasks': counter,
            'phone': self.phone,
            'img': self.image,
            'process': counter1,
            'img_route': f'static/profile_pics/{self.email}/account_img/{self.image}',
            'section_id': self.section_id

            }


    @property
    def is_admin(self):
        return self.roles == 'admin'

    def jsonify_s(self):
        load = json.load({
            'id': self.id,
            'email': self.email,
            'image': self.image,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'role': self.roles,
            'region': self.region,
            'section': self.user_section.section,
            # 'organization': self.se,
            'report_user': [x.format() for x in self.report_user],
        }
            , endcode='utf-8')
        return load


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(200), nullable=True)
    term_execution = db.Column(db.String(200), nullable=True)
    executed = db.Column(db.String(200), nullable=True)
    status = db.Column(db.String(200), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user_file = db.relationship('Attachments', backref='files', lazy=True, cascade="all, delete-orphan")
    user_urls = db.relationship('Addurl', backref='url', lazy=True, cascade="all, delete-orphan")
    from_last_name = db.Column(db.String(200), nullable=True)
    from_first_name = db.Column(db.String(200), nullable=True)
    from_role = db.Column(db.String(200), nullable=True)
    from_id = db.Column(db.Integer)
    order_signs = db.relationship('OrderSign', backref='task', lazy=True, cascade="all, delete-orphan")
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))

    def format(self):
        return {
            'id': self.id,
            'task': self.task,
            'first_name': self.reporter.first_name,
            'last_name': self.reporter.last_name,
            'term_execution': self.term_execution,
            'executed': self.executed,
            'status': self.status,
            'user_id': self.user_id,
            # 'email_user': self.reporter.email,

            # 'user_role': self.reporter.roles,
            # 'region': self.reporter.region,
            # 'section_id': self.reporter.section_id,
            'from_last_name': self.from_last_name,
            'from_first_name': self.from_first_name,
            'from_role': self.from_role,
            'user_file': [x.format() for x in self.user_file],
            'user_url': [x.format() for x in self.user_urls]
            # 'organization': self.reports.organization
        }

    def test(self):
        return [
            self.id,
            self.task,
            self.reporter.first_name,
            self.reporter.last_name,
            self.term_execution,
            self.executed,
            self.status,
            self.user_id,
            self.reporter.email,

            self.reporter.roles,
            self.reporter.region,

        ]

    def __repr__(self):
        return self.task + " id: " + str(self.id)




class Attachments(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200))
    file = db.Column(db.LargeBinary)
    file_url = db.Column(db.String(200))
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'))
    date_posted = db.Column(db.DateTime, default=datetime.now())
    sender_id = db.Column(db.Integer)

    def format(self):
        return {
            'id': self.id,
            'filename': self.filename,

            'report_id': self.report_id,
            # 'date_posted': self.date_posted

        }


class Addurl(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url_text = db.Column(db.String(200))
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'))
    sender_id = db.Column(db.Integer)

    def format(self):
        return {
            'id': self.id,
            'url': self.url_text
        }


class OrderSign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sign = db.Column(db.String(200), nullable=False)
    hash = db.Column(db.String(200), nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey('report.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    orders_id = db.Column(db.Integer, db.ForeignKey('order.id', ondelete='CASCADE'))

    def format(self):
        return {
            'id': self.id,
            'sign': self.sign,
            'hash': self.hash,
            'orders id': self.orders_id,
            'signed last name': self.signed_by.last_name,
            'signed first name': self.signed_by.first_name
        }





class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.relationship('Report', backref='orders', lazy=True, cascade="all, delete-orphan")
    created_at = db.Column(db.DateTime, default=datetime.now())
    status = db.Column(db.String(60), default="new", nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    orders_sign = db.relationship('OrderSign', backref='orders_to_sign', lazy=True, cascade="all, delete-orphan")

    def getUserFile(self):
        for file in self.orders.user_file:
            return file.id

    def getUserUrl(self):
        for url in self.orders.user_urls:
            return url.url_text

    def format(self):
        return {
            'id': self.id,
            'content': [x.format() for x in Report.query.filter_by(user_id=self.user_id, status='sent')],
            'created at': self.created_at,
            'status': self.status,
            'order signs': [x.format() for x in OrderSign.query.filter_by(orders_id=self.id)],
            # 'from last name': self.orderss.last_name,
            # 'from first name': self.orderss.first_name,
            # 'file to download <id>': self.getUserFile(),
            # 'URL': self.getUserUrl()

        }

class DestroyedToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.Text, unique=True, nullable=False)

    def __repr__(self):
        return self.token