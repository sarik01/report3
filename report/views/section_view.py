from flask import url_for, redirect
from flask_admin.contrib.sqla import ModelView
from flask_login import current_user


class SectionView(ModelView):
    column_display_pk = True
    column_labels = {
        'id': 'ID',
        'section': 'Отделы'
    }
    #
    # def is_accessible(self):
    #     return current_user.is_admin
    #
    # def _handle_view(self, name, **kwargs):
    #     if not self.is_accessible():
    #         return redirect(url_for('users.login'))

    can_create = True
    can_edit = True
    can_delete = True
    can_export = True
    create_modal = True
    edit_modal = True

    column_searchable_list = [ 'section',]
    column_filters = [ 'id', 'section',]

