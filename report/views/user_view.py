from flask_admin.contrib.sqla import ModelView
from flask_login import current_user
from report import bcrypt
from flask import Markup, url_for, redirect
from report import User


class UserView(ModelView):
    column_display_pk = True
    column_labels = {
        'id': 'Id',
        'email': 'Логин',
        'last_name': 'Фамилия',
        'first_name': 'Имя, Отчество',
        'roles': 'Должность',
        'region': 'Регион',
        'section': 'Отдел',
        'report_user': 'Текущие задание',
        'password': 'Пароль',
        'image': 'Изображение',
        'phone': 'Телефон'
    }

    column_list = ['id', 'image', 'email', 'last_name', 'first_name', 'phone', 'roles', 'section', 'region',
                    'report_user']

    column_default_sort = ('id', True)
    column_sortable_list = ('id', 'roles', 'first_name', 'email', 'last_name', 'roles', 'region', 'section', 'phone')

    can_create = True
    can_edit = True
    can_delete = False
    can_export = True
    export_types = ['xlsx']
    export_max_rows = 500



    AVAILABLE_USER_TYPES = [
        (u'admin', u'admin'),
        (u'Директор', u'Директор'),
        (u'Директорнинг биринчи ўринбосари', u'Директорнинг биринчи ўринбосари'),
        (u'Директорнинг ўринбосари', u'Директорнинг ўринбосари'),
        (u'Бош юрисконсульт', u'Бош юрисконсульт'),
        (u'Бўлим бошлғи', u'Бўлим бошлғи'),
        (u'Cектор бошлиғи', u'Cектор бошлиғи'),
        (u'Бош мутахассис', u'Бош мутахассис'),
        (u'Етакчи мутахассис', u'Етакчи мутахассис'),
        (u'Мутахассис', u'Мутахассис'),
        (u'Бўлим бошлиғи-Бош ҳисобчи', u'Бўлим бошлиғи-Бош ҳисобчи'),
        (u'Бошлиғи', u'Бошлиғи'),
        (u'Бўлим бошлиғи ўринбосари', u'Бўлим бошлиғи ўринбосари'),
        (u'Оператор', u'Оператор'),
        (u'Хайдовчи', u'Хайдовчи'),
        (u'Меҳнат мухофазаси ва техника хавфсизлиги бўйича мухандис', u'Меҳнат мухофазаси ва техника хавфсизлиги бўйича мухандис'),
        (u'Колл-марказ бошлиғи', u'Колл-марказ бошлиғи'),
        (u'user', u'user'),
    ]

    form_choices = {
        'roles': AVAILABLE_USER_TYPES
    }




    column_exclude_list = ['password']

    column_searchable_list = ['email', 'first_name', 'last_name', 'roles', 'roles', 'region', 'id', 'section.section', 'phone']
    column_filters = ['email', 'first_name', 'last_name', 'roles', 'roles', 'region', 'id', 'section', 'phone']
    column_editable_list = ['roles', 'first_name', 'email', 'last_name', 'roles', 'region', 'phone']

    create_modal = True
    edit_modal = True

    # def _list_thumbnail(StorageView, context, model, name):
    #     if not model.report_user:
    #         return ''
    #     else:
    #
    #
    #         # for reporter in reporters:
    #
    #         path = model.report_user
    #
    #         return Markup(f'<p>{path[]}</p>')
    #
    #
    # column_formatters = {
    #     'report_user': _list_thumbnail
    # }
    #
    # def is_accessible(self):
    #     return current_user.is_admin
    #
    #
    # def _handle_view(self, name, **kwargs):
    #     if not self.is_accessible():
    #         return redirect(url_for('users.login'))

    def _list_section(UserView, context, model, name):
        if not model.section:
            return ''
        else:

            return Markup(f'{model.section.section}')

    def _list_task(UserView, context, model, name):
        if not model.report_user:
            return ''
        else:
            for task in model.report_user:
                user_task = task.task
            return Markup(f'{user_task}')


    def _img(UserView, context, model, name):
        if not model.image:
            return ''
        else:
            return Markup(f'<img src=/static/profile_pics/{model.email}/account_img/{model.image} width=75>')

    column_formatters = {
        'report_user': _list_task,
        'section': _list_section,
        'image': _img
    }


    form_excluded_columns = ['id']

    def create_form(self, obj=None):
        return super(UserView, self).create_form(obj)

    def edit_form(self, obj=None):
        return super(UserView, self).edit_form(obj)

    def on_model_change(self, form, model, is_created):
        model.password = bcrypt.generate_password_hash(model.password)


    # def select(self, form, model, is_created):
    #     for select in model.section:
    #         sel = select.section
    #         return Markup(f'<select value="{select.id}><option>{sel}</option></select>')