import datetime
import io, jwt
import os
import secrets
import shutil
import uuid
# coding=utf-8
from io import BytesIO
import json

import openpyxl
from PIL.Image import Image
from flask import Blueprint, request, jsonify, url_for, session, current_app, Response, render_template, send_file
from flask_login import login_user, login_required, logout_user, current_user
from flask_mail import Message
from werkzeug.exceptions import abort
from werkzeug.utils import secure_filename

from report import login_manager, db, mail, principal, ma, bcrypt
from report.models import User, Report, Attachments, Sections, Addurl, DestroyedToken
from flask_principal import Permission, RoleNeed, Identity, identity_changed, AnonymousIdentity, identity_loaded, \
    UserNeed, ActionNeed

from report.user.utils import allowed_file, allowed_pic, save_avatarUser_picture

users = Blueprint('users', __name__)

be_admin = RoleNeed('admin')
directorning_brinchi_urinbosari = RoleNeed('Директорнинг биринчи ўринбосари')
directorning_urinbosari = RoleNeed('Директорнинг ўринбосари')
be_director = RoleNeed('Директор')
chief_lawyer = RoleNeed('Бош юрисконсульт')
bulim_boshlgi = RoleNeed('Бўлим бошлғи')
sector_boshlgi = RoleNeed('Cектор бошлиғи')
bosh_mutaxassis = RoleNeed('Бош мутахассис')
etkachi_mutaxassis = RoleNeed('Етакчи мутахассис')
mutaxassis = RoleNeed('Мутахассис')
bulim_boshlgi_bosh_xisobchi = RoleNeed('Бўлим бошлиғи-Бош ҳисобчи')
boshligi = RoleNeed('Бошлиғи')
bulim_boshlgi_urinbosari = RoleNeed('Бўлим бошлиғи ўринбосари')
operator = RoleNeed('Оператор')
driver = RoleNeed('Хайдовчи')
mexnat = RoleNeed('Меҳнат мухофазаси ва техника хавфсизлиги бўйича мухандис')
call_center_chief = RoleNeed('Колл-марказ бошлиғи')

staff_permission = Permission(be_director, directorning_brinchi_urinbosari, be_admin, directorning_urinbosari,
                              chief_lawyer,
                              bulim_boshlgi, sector_boshlgi, bosh_mutaxassis, mutaxassis, bulim_boshlgi_bosh_xisobchi,
                              boshligi, bulim_boshlgi_urinbosari, operator, driver, mexnat, call_center_chief)

staff_permission.description = "Ishchi bolishiz kerak"
admin_permission = Permission(be_admin)
admin_permission.description = "Admin bolishiz kerak"
directorning_urinbosari_permission = Permission(directorning_urinbosari, directorning_brinchi_urinbosari, be_admin)
directorning_urinbosari_permission.description = "Директорнинг ўринбосари bolishiz kerak"
director_permission = Permission(be_director)
director_permission.description = "Direktor bolishiz kerak"
boshligi_permission = Permission(bulim_boshlgi, sector_boshlgi, boshligi, bulim_boshlgi_bosh_xisobchi,
                                 bulim_boshlgi_urinbosari, be_admin, be_director)
mutaxassis_permission = Permission(etkachi_mutaxassis, bosh_mutaxassis, be_admin, be_director)

to_sign_in = ActionNeed('signup')


class Schema(ma.Schema):
    class Meta:
        fields = ('id', 'email',

                  'first_name',
                  'last_name',
                  'roles',
                  'region',
                  'task',
                  'term_execution',
                  'executed',
                  'status',
                  'user_id',
                  'section.section',
                  'user_file',
                  'user_url',
                  'image',
                  'phone',
                  'users_task',
                  'phones',
                  'section'

                  )


schema = Schema()
schemas = Schema(many=True)


#
# @login_manager.user_loader
# def load_user(user_id):
#     return User.query.get(int(user_id))


@login_manager.request_loader
def load_user_from_request(request):
    api_key = request.headers.get('x-access-token')
    print(api_key)
    expired_token = DestroyedToken.query.filter_by(token=api_key).first()
    print(expired_token)
    if not expired_token:

        try:
            data = jwt.decode(api_key, current_app.config['SECRET_KEY'], algorithms='HS256')
            user_id = data.get('user_id')


        except Exception:
            return None
        user = User.query.get(user_id)
        if user:
            return user
    return None


# @principal.identity_loader
# def read_identity_from_flask_login():
#     if current_user.is_authenticated():
#         return Identity(current_user.id)
#     return AnonymousIdentity()

#
# @identity_loaded.connect
# def on_identity_loaded(sender, identity):
#     """Handle the identity_loaded signal.
#     """
#     # Set the identity user object
#     identity.user = current_user
#     print(current_user)
#     # Add the UserNeed to the identity
#     if hasattr(current_user, "id"):
#         identity.provides.add(UserNeed(current_user.id))
#         print(current_user.id)
#
#     # Assuming the User model has a list of roles, update the
#     # identity with the roles that the user provides
#     if hasattr(current_user, "roles"):
#         identity.provides.add(RoleNeed(current_user.roles))
#         print(current_user.roles)
#

#
# @identity_loaded.connect_via(users)
# def on_identity_loaded(sender, identity):
#
#     if not isinstance(identity, AnonymousIdentity):
#         identity.provides.add(UserNeed(identity.id))
#
#     # # Add the UserNeed to the identity
#     # if hasattr(current_user, 'id'):
#     #     identity.provides.add(UserNeed(current_user.id))
#
#     # Assuming the User model has a list of roles, update the
#     # identity with the roles that the user provides
#     if current_user.is_admin:
#         identity.provides.add(RoleNeed('admin'))


@users.route('/account')
@login_required
# @staff_permission.require(http_exception=403)
def account():
    user = User.query.filter_by(id=current_user.id).first()

    print(user)

    return jsonify(user.format())


@users.route('/')
@staff_permission.require(403)
def do_admin_index():
    if current_user.is_admin:
        print(current_user.roles)
        return Response('Only if you are an admin')
    print(current_user.roles)

    return jsonify({'msg': 'you are not admin!'}), 403


@users.route('/add', methods=['POST', 'GET'])
def signup():
    section = Sections.query.all()
    if request.method == 'POST':
        hash_pw = bcrypt.generate_password_hash(request.form.get('pw'))
        user = User(email=request.form.get('name'), password=hash_pw, first_name=request.form.get('first_name'),
                    last_name=request.form.get('last_name'),
                    roles=request.form.get('role'), region=request.form.get('region'),
                    section_id=request.form.get('section'))

        db.session.add(user)
        db.session.flush()

        full_path = os.path.join(os.getcwd(), 'report\static', 'profile_pics', user.email, 'account_img')
        # full_path = os.path.join(current_app.root_path, 'static', 'profile_pics/', user.username, 'account_img')
        if not os.path.exists(full_path):
            os.makedirs(full_path)

        shutil.copy(f'{os.getcwd()}/report/static/profile_pics/default.jpg', full_path)
        db.session.commit()

        return jsonify({'msg': 'User Added'})
    return schemas.dumps(section)


@users.route('/admin/update_user', methods=['POST', 'GET'])
@login_required
# @admin_permission.require(http_exception=403)
def AdminupdateUser():
    email = request.args.get('email')
    user = User.query.filter_by(email=email).first_or_404()

    if request.method == 'POST':
        current_user.first_name = request.form.get('first_name')
        current_user.last_name = request.form.get('last_name')
        current_user.region = request.form.get('region')
        current_user.organization = request.form.get('organization')

        try:
            db.session.commit()
            return jsonify({'msg': 'updated!'})
        except:
            return jsonify({'msg': 'wrong!'})

    return schema.jsonify(user)


@users.route('/update_user', methods=['POST', 'GET'])
@login_required
# @staff_permission.require(http_exception=403)
def updateUser():
    user = User.query.filter_by(email=current_user.email).first_or_404()
    img = request.files.get('image')
    if request.method == 'POST':

        current_user.first_name = request.form.get('first_name')
        current_user.last_name = request.form.get('last_name')
        current_user.region = request.form.get('region')
        current_user.organization = request.form.get('organization')
        current_user.phone = request.form.get('phone')
        current_user.phones = request.form.getlist('phones')

        if request.files.get('image') and allowed_pic(img.filename):
            print('img')

            current_user.image = save_avatarUser_picture(img)

        if request.form.get('email'):
            path_one = os.path.join(os.getcwd(), f'report/static/profile_pics/{user.email}')
            path_two = os.path.join(os.getcwd(), f'report/static/profile_pics/{request.form.get("email")}')
            os.rename(path_one, path_two)
            current_user.email = request.form.get('email')

        db.session.commit()
        return jsonify({'msg': 'updated'})

    return schema.dumps(user, ensure_ascii=False).encode('utf-8')


@users.route('/update_password', methods=['POST', 'GET'])
@login_required
# @staff_permission.require(http_exception=403)
def updatePw():
    user = User.query.filter_by(email=current_user.email).first_or_404()
    hash_pw = bcrypt.generate_password_hash(request.form.get('password'))
    print(current_user.email)
    if request.method == 'POST':
        if user:

            if bcrypt.check_password_hash(user.password, request.form.get('pw')):
                current_user.password = hash_pw
                db.session.commit()
                return jsonify({'msg': 'changed'})
        return jsonify({'msg': 'Invalid'})


@users.route('/admin/get/user')
@login_required
@admin_permission.require(http_exception=403)
def getUser():
    id = request.args.get('id')
    user = User.query.get_or_404(id)
    return schema.dumps(user, ensure_ascii=False).encode('utf-8')


@users.route('/admin/delete_user')
@login_required
# @admin_permission.require(http_exception=403)
def AdmindeleteUser():
    email = request.args.get('email')
    user = User.query.filter_by(email=email).first_or_404()
    try:
        db.session.delete(user)
        db.session.commit()

        full_path = os.path.join(os.getcwd(), 'report/static', 'profile_pics', user.email)
        shutil.rmtree(full_path)

        return jsonify({'msg': 'user deleted!'})
    except:
        return jsonify({'msg': 'wrong!'})


@users.route('/delete_user')
@login_required
@staff_permission.require(http_exception=403)
def deleteUser():
    user = User.query.filter_by(email=current_user.email).first_or_404()
    try:
        db.session.delete(user)
        db.session.commit()

        full_path = os.path.join(os.getcwd(), 'report/static', 'profile_pics', user.email)
        shutil.rmtree(full_path)

        return jsonify({'msg': 'user deleted!'})
    except:
        return jsonify({'msg': 'wrong!'})


@users.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        return jsonify({"msg": "invalid token"})
    user = User.query.filter_by(email=request.form.get('name')).first()
    if user:
        if bcrypt.check_password_hash(user.password, request.form.get('pw')):
            # login_user(user)

            token = jwt.encode({'user_id': user.id,
                                'exp': datetime.datetime.now() + + datetime.timedelta(seconds=0)

                                }, current_app.config['SECRET_KEY'], algorithm='HS256')

            identity_changed.send(current_app._get_current_object(),
                                  identity=Identity(user.id))
            print(Identity(user.id))

            print('krasavchik')
            return jsonify({'msg': 'ok', 'token': token})
        else:
            print('hueplet')
            return jsonify({'msg': 'incorrect password'})
    else:
        print('chort')
        return jsonify({'msg': 'user not found'})
    # return render_template('login.html')


@users.route('/logout')
@login_required
# @staff_permission.require(http_exception=403)
def logout():
    logout_user()

    # Remove session keys set by Flask-Principal
    for key in ('identity.name', 'identity.auth_type'):
        session.pop(key, None)

    # Tell Flask-Principal the user is anonymous
    identity_changed.send(current_app._get_current_object(),
                          identity=AnonymousIdentity())

    api_key = request.headers.get('x-access-token')

    destroytoken = DestroyedToken(token=api_key)
    db.session.add(destroytoken)
    db.session.commit()

    return jsonify({'msg': 'you logged out'})


def send_mail(user):
    token = user.getToken()
    msg = Message('Password Reset Request', recipients=[user.email], sender='sarvar_kamilov2@mail.ru')
    msg.body = f'''To reset your password. Please follow the link below

    {url_for('users.reset_token', token=token, _external=True)}

  if you didn't send password reset request. Please ignore this message.  


'''

    mail.send(msg)


@users.route('/reset/password/<token>', methods=['POST', 'GET'])
def reset_token(token):
    user = User.verify_token(token)
    if user is None:
        return jsonify({'msg': 'that is invalid token'})
    if request.method == 'POST':
        hash_pw = bcrypt.generate_password_hash(request.form.get('pw'))
        user.password = hash_pw
        db.session.commit()
        return jsonify({'msg': 'Changed Successfully'})


@users.route('/reset/password', methods=['POST', 'GET'])
def reset_pw():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('name')).first()
        if user:
            send_mail(user)

            return jsonify({'msg': 'Done'})
        return jsonify({'msg': 'user not found'})
    return jsonify({'msg': 'Reset PW'})


@users.route('/get_users_task')
@admin_permission.require(http_exception=403)
def getUsersTask():
    id = request.args.get('id')
    user = User.query.filter_by(id=id).first()
    user_tasks = Report.query.filter_by(user_id=user.id)
    return schemas.dumps([x.format() for x in user_tasks], ensure_ascii=False).encode('utf-8')


@users.route('/get/userstasktable')
@login_required
# @staff_permission.require(http_exception=403)
def getUsersTaskTable():
    id = request.args.get('id')
    user = User.query.filter_by(id=current_user.id).first()
    user_tasks = Report.query.filter_by(user_id=user.id).all()
    result = [x.test() for x in user_tasks]
    output = io.BytesIO()

    workbook = openpyxl.Workbook()

    workbook.remove(workbook.active)

    sheet = workbook.create_sheet('Задания')

    sheet.insert_rows(0)
    sheet['A1'].value = 'ID'
    sheet['B1'].value = 'TASK'
    sheet['C1'].value = 'Имя'
    sheet['D1'].value = 'Фамилия'
    sheet['E1'].value = 'Срок'
    sheet['F1'].value = 'Выполнил'

    # sheet['B1'].style = "Good"
    # sheet['D1'].style = "Bad"

    print(result)

    for row in result:
        sheet.append(row)

    workbook.save(output)
    output.seek(0)

    return Response(output, mimetype="application/ms-excel",
                    headers={"Content-Disposition": "attachment;filename=users_table.xls"})


@users.route('/getallusers')
@login_required
# @admin_permission.require(http_exception=403)
def allUsers():
    return jsonify([x.format() for x in User.query.all()])


@users.route('/getuser')
@login_required
@admin_permission.require(http_exception=403)
def getUser2():
    id = request.args.get('id')
    user = User.query.get_or_404(id)
    return jsonify(user.format())


@users.route('/upload', methods=['POST', 'GET'])
@login_required
# @staff_permission.require(http_exception=403)
def uploadFile():
    id = request.args.get('id')
    task = Report.query.filter_by(id=id).first()
    file = request.files.get('file')
    url = request.form.get('url')
    if request.method == 'GET':

        if allowed_file(file.filename):

            upload = Attachments(file=file.read(), report_id=task.id, filename=file.filename,
                                 sender_id=current_user.id)

            db.session.add(upload)
            db.session.commit()
            return jsonify({'msg': 'FILE Uploaded!'})
        else:
            return jsonify({'msg': 'not allowed format'})



@users.route('/addurls', methods=['POST', 'GET'])
@login_required
@staff_permission.require(http_exception=403)
def addUrl():
    id = request.args.get('id')
    task = Report.query.filter_by(id=id).first()

    if request.method == 'POST':
        text = Addurl(url_text=request.form.get('url'), report_id=task.id, sender_id=current_user.id)

        db.session.add(text)
        db.session.commit()

        return jsonify({'msg': 'added'})


@users.route('/download')
# @admin_permission.require()
def downloadFile():
    id = request.args.get('id')
    upload = Attachments.query.filter_by(id=id).first()
    return send_file(BytesIO(upload.file), attachment_filename=upload.filename,
                     as_attachment=True)  # attachment_filename=upload.filename

@users.route('/getfile')
def getFile():
    id = request.args.get('id')
    upload = Attachments.query.get(id)
    return render_template('login.html', upload=upload)

@users.route('/delete/attachment')
@staff_permission.require(http_exception=403)
def deleteAttach():
    id = request.args.get('id')
    file = Attachments.query.get(id)

    if file.sender_id != current_user.id or current_user.id != 1:
        print(file.sender_id)
        abort(403)

    db.session.delete(file)
    db.session.commit()
    return jsonify({'msg': 'deleted!'})


@users.route('/delete_url')
@staff_permission.require(http_exception=403)
def deleteUrl():
    id = request.args.get('id')
    url = Addurl.query.get(id)

    if url.sender_id != current_user.id:
        abort(403)

    db.session.delete(url)
    db.session.commit()
    return jsonify({'msg': 'deleted!'})


@users.route('/get_users_by_sections')
# @admin_permission.require()
def getUsersBySection():
    section = request.args.get('section_id')
    users = User.query.filter_by(section_id=section)

    return schemas.dumps(users, ensure_ascii=False).encode('utf-8')


# create folders for all users with default pictures
@admin_permission.require(403)
@users.route('/make')
def makeDirs():
    data = []

    users = [x.format() for x in User.query.all()]

    for user in users:

        full_path = os.path.join(os.getcwd(), 'report\static', 'profile_pics', user['email'], 'account_img')

        if not os.path.exists(full_path):
            os.makedirs(full_path)

        shutil.copy(f'{os.getcwd()}/report/static/profile_pics/default.jpg', full_path)

        user = User.query.get_or_404(user['id'])
        print(user)
        user.image = 'default.jpg'

        db.session.commit()
        return 'done!'

