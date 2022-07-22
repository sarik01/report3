from flask import url_for, redirect, Markup
from flask_admin.contrib.sqla import ModelView
from flask_login import current_user
from report.models import Report

class TaskView(ModelView):
    column_display_pk = True
    column_labels = {
        'id': 'ID',
        'task': 'Задания',
        'term_execution': 'Срок выполнения',
        'executed': 'Когда выполненно',
        'status': 'Статус',
        'user_file': 'Загруженные файлы',
        'reporter': 'Исполнитель',
        'user_urls': 'URL Файла',
        'from_role': 'Должность назначающего',
        'from_last_name': 'Фамилия назначающего',
        'from_first_name': 'Имя, Отчество назначающего',
        'settler': 'Назначающий',
        'reporter.image': 'Изображение'

    }

    create_modal = True
    edit_modal = True
    can_export = True
    export_types = ['xlsx']
    export_max_rows = 500

    # def is_accessible(self):
    #     return current_user.is_admin
    #
    # def _handle_view(self, name, **kwargs):
    #     if not self.is_accessible():
    #         return redirect(url_for('users.login'))

    column_list = ['id', 'reporter.image', 'reporter', 'task', 'term_execution', 'executed', 'status',  'user_file', 'user_urls', 'settler']

    column_searchable_list = ['task', 'term_execution', 'executed', 'status', 'id',  'reporter.last_name', 'reporter.first_name']

    column_editable_list = ['task', 'term_execution', 'executed', 'status']
    column_filters = ['task', 'term_execution', 'executed', 'status', 'id', 'reporter.first_name', 'reporter.last_name']

    column_sortable_list = ['task', 'term_execution', 'executed', 'status',  'id']



    form_excluded_columns = ['id']

    # def _change_user(Taskview, context, model, name):
    #     for user in model.reporter:
    #         return f'{user.first_name} {user.last_name}'
    #
    #
    #
    # AVAILABLE_USER = [ _change_user
    #
    #
    # ]
    #
    # form_choices = {
    #     'reporter': AVAILABLE_USER
    # }

    def _list_file(Taskview, context, model, name):
        if not model.user_file:
            return ''
        else:
            for file in model.user_file:
                user_file = file.filename
                download_file= url_for('users.downloadFile', id=file.id)
                delete_file = url_for('users.deleteAttach', id=file.id)
            return  Markup(f'<p>{user_file}</p> <a href={download_file}>скачать</a><br><a href={delete_file}>удалить</a></br>')

    def _list_url(Taskview, context, model, name):
        if not model.user_urls:
            return ''
        else:
            for url in model.user_urls:
                user_url = Markup(f'<a href="{url.url_text}" target="_blank">Перейти по ссылке</a>')
                return user_url


    def _list_thumbnail(Taskview, context, model, name):
        if not model.reporter:
            return ''
        else:

            return Markup(f'{model.reporter.last_name} {model.reporter.first_name} id: {model.reporter.id}')
                # return Markup(f'<select><option value={reporter.reporter.id}>{reporter.reporter.last_name} {reporter.reporter.first_name}</option></select>')



    def _list_from(Taskview, context, model, name):
        if not model.from_role:
            return ''

        return Markup(f'{model.from_last_name} {model.from_first_name} {model.from_role}')

    def _img(UserView, context, model, name):
        if not model.reporter.image:
            return ''
        else:
            return Markup(f'<img src=/static/profile_pics/{model.reporter.email}/account_img/{model.reporter.image} width=75>')

    column_formatters = {
        'reporter': _list_thumbnail,
        'user_file': _list_file,
        'user_urls': _list_url,
        'settler': _list_from,
        'reporter.image': _img
    }


