from flask_admin import Admin, BaseView, expose, AdminIndexView
from flask import Flask, Markup, request
from flask_login import LoginManager, current_user
from flask_mail import Mail
from flask_marshmallow import Marshmallow
from flask_principal import Principal, identity_loaded, UserNeed, RoleNeed
from flask_sqlalchemy import SQLAlchemy
from flask_admin.contrib.sqla import ModelView
from flask_babel import Babel
from flask_bcrypt import Bcrypt
from sqlalchemy import desc, MetaData
import tablib
from flask_migrate import Migrate



convention = {
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

metadata = MetaData(naming_convention=convention)

data = tablib.Dataset()

login_manager = LoginManager()
login_manager.login_view = 'users.login'
login_manager.login_message = 'Пожалуйста сначало зарегистрируйтесь!'
login_manager.login_message_category = 'info'
db = SQLAlchemy(metadata=metadata)
mail = Mail()
babel = Babel()
principal = Principal()
ma = Marshmallow()
bcrypt = Bcrypt()
migrate = Migrate()

from report.user.routes import users
from report.tasks.routes import tasks
from report.models import User, Report, Attachments, Sections, Order, OrderSign


class MyMainView(AdminIndexView):
    @expose('/')
    def admin_main(self):
        page = request.args.get('page', 1, type=int)
        files = Attachments.query.order_by(desc(Attachments.date_posted)).paginate(page=page, per_page=10)
        return self.render('admin/index.html', files=files)


def create_app():
    app = Flask(__name__)
    app.config.from_pyfile('config.cfg')
    login_manager.init_app(app)
    db.init_app(app)
    mail.init_app(app)
    babel.init_app(app)
    migrate.init_app(app, db, render_as_batch=True)
    principal.init_app(app)
    ma.init_app(app)
    bcrypt.init_app(app)
    from .views.user_view import UserView
    from .views.task_view import TaskView
    from .views.section_view import SectionView
    admin = Admin(app, 'АДМИНКА', index_view=MyMainView(), template_mode='bootstrap4', url='/admin')
    admin.add_view(UserView(User, db.session, name='Пользователи', url='users'))
    admin.add_view(TaskView(Report, db.session, name='Задания', url='tasks'))
    admin.add_view(SectionView(Sections, db.session, name='Отделы', url='sections'))
    admin.add_view(ModelView(Order, db.session))
    admin.add_view(ModelView(OrderSign, db.session))

    app.register_blueprint(users)
    app.register_blueprint(tasks)

    @identity_loaded.connect_via(app)
    def on_identity_loaded(sender, identity):
        """Handle the identity_loaded signal.
        """
        # Set the identity user object
        identity.user = current_user
        print(current_user)
        print(identity)
        # Add the UserNeed to the identity
        if hasattr(current_user, "id"):
            identity.provides.add(UserNeed(current_user.id))
            print(current_user.id)

        # Assuming the User model has a list of roles, update the
        # identity with the roles that the user provides
        if hasattr(current_user, "roles"):
            identity.provides.add(RoleNeed(current_user.roles))
            print(current_user.roles)

        if hasattr(current_user, 'is_authenticated'):
            if current_user.is_authenticated:
                identity.provides.add(RoleNeed(current_user.roles))
                print(current_user.roles)
            else:
                print('not')

    @app.after_request
    def after_request(response):
        header = response.headers
        header.add('Access-Control-Allow-Origin', '*')
        header.add('Access-Control-Allow-Headers', '*')
        header.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        return response

    return app
