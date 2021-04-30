import os
import re
import pyqrcode

from io import BytesIO
from functools import wraps
from flask import Blueprint, request, render_template, redirect, url_for, flash, session
from flask_login import current_user, login_user, logout_user, login_required
from flask_mail import Message
from sqlalchemy.exc import StatementError
from .models.User import User
from .models.PasswordResetRequest import PasswordResetRequest
from .models.UserFile import UserFile
from .utils.encryptionutils import get_fernet, get_encryption_key
from . import db, config, mail

from werkzeug.datastructures import FileStorage
from pathlib import Path

view = Blueprint('view', __name__, static_folder="web/static")
auth = Blueprint('auth', __name__, static_folder="web/static")
storage = Blueprint('storage', __name__, static_folder="web/static")


#################
#               #
#     UTILS     #
#               #
#################
def login_pointless(func, view='view.index'):
    """
    Routes decorated with this will ensure that the client
    is *NOT* authenticated before calling the actual view.
    
    Example:
        @app.route('/login')
        @login_pointless('main.login')
        def login():
            login_logic()
    
    Parameters:
        func: The view function to decorate
        view: If the user is logged in, where should be redirected
    
    Types:
        func: function
        view: str
    """

    @wraps(func)
    def decorator(*args, **kwargs):
        if current_user.is_authenticated:
            flash('You are already signed in.', 'warn')
            return redirect(url_for(view), 302)
        return func(*args, **kwargs)

    return decorator


class Validators:
    @staticmethod
    def name(val):
        return re.search(
            r"^([a-zA-Z]{2,}\s[a-zA-Z]{1,}'?-?[a-zA-Z]{2,}\s?([a-zA-Z]{1,})?)$",
            val)

    @staticmethod
    def email(val):
        return re.search(r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$', val)

    @staticmethod
    def password(val):
        return re.search(r'^[a-zA-Z0-9~!@#$%^&*()_+=\- ]{8,128}$', val)


################
#              #
#     AUTH     #
#              #
################
@auth.route('/login', methods=['GET', 'POST'])
@login_pointless
def login():
    """ Login route waypoint """
    if request.method == 'GET':
        return render_template('auth/login.html')
    elif request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        totptoken = request.form.get('2fa')

        user: User = User.query.filter_by(email=email).first()

        if not user:
            flash('User not found!', 'error')
            return redirect(url_for('auth.login'))

        if not user.validate_password(password):
            flash('Password incorrect!', 'error')
            return redirect(url_for('auth.login'))

        if user.has_2fa and not user.verify_totp(totptoken):
            flash('Wrong 2FA token, please try again!', 'error')
            return redirect(url_for('auth.login'))

        login_user(user, remember=remember)

        session['my_key'] = user.get_encryption_key(password)
        flash(f'Successfully logged in as {user.name}!', 'success')
        return redirect(url_for('view.index'))
    else:
        return redirect(url_for('view.index'))


@auth.route('/register', methods=['GET', 'POST'])
@login_pointless
def register():
    """ Register route waypoint """
    if request.method == 'GET':
        return render_template('auth/register.html')
    elif request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        profile_picture = request.form.get('profilepic')
        name = request.form.get('name')

        errors = []

        if not Validators.email(email):
            errors.append('E-Mail is not valid!')

        if not Validators.password(password):
            errors.append(
                'Password is not valid! The password should contain between 8 to 128 characters from the following: (a-z, A-Z, 0-9, ~!@#$%^&*()_+-=)'
            )

        if not Validators.name(name):
            errors.append('Name is not valid!')

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth/register.html')

        user: User = User.query.filter_by(email=email).first()

        if user:
            flash('User with email {} already exists'.format(email), 'error')
            return redirect(url_for('auth.register'))

        user = User(email=email,
                    password=password,
                    name=name,
                    profile_picture=profile_picture)
        db.session.add(user)
        db.session.commit()

        flash(f'Successfully registered!', 'success')
        return redirect(url_for('auth.login'))
    else:
        return redirect(url_for('view.index'))


@auth.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('view.index'))


@auth.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'GET':
        return render_template('auth/profile.html')
    elif request.method == 'POST':
        profile_picture = request.form.get('profilepic')
        name = request.form.get('name')

        errors = []

        if not Validators.name(name):
            errors.append('Name is not valid!')

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth/profile.html')

        current_user.name = name
        current_user.profile_picture = profile_picture

        db.session.commit()

        flash(f'Successfully commited changes!', 'success')
        return redirect(url_for('auth.profile'))
    else:
        return render_template('auth/profile.html')


@auth.route('/profile/password', methods=['GET', 'POST'])
@login_required
def password():
    if request.method == 'GET':
        return render_template('auth/password.html')
    elif request.method == 'POST':
        current_password = request.form.get('currentpassword')
        new_password = request.form.get('newpassword')

        if not current_user.validate_password(current_password):
            flash('Current password is incorrect!', 'error')
            return redirect(url_for('auth.password'))

        if not Validators.password(new_password):
            flash(
                'New password is not valid! The password should contain between 8 to 128 characters from the following: (a-z, A-Z, 0-9, ~!@#$%^&*()_+-=)',
                'error')
            return redirect(url_for('auth.password'))

        current_user.password = new_password
        db.session.commit()

        flash('Successfully changed password!', 'success')
        return redirect(url_for('auth.profile'))


@auth.route('/profile/2fa', methods=['GET'])
@login_required
def two_factor_auth():
    return render_template('auth/2fa.html')


@auth.route('/profile/2faqr', methods=['GET'])
@login_required
def two_factor_auth_qr():
    uri = pyqrcode.create(current_user.get_totp_uri())
    stream = BytesIO()
    uri.svg(stream, scale=5)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    }


@auth.route('/profile/enable2fa', methods=['GET'])
@login_required
def enable_2fa():
    if current_user.otp_secret is None:
        current_user.generate_otp_secret()
    return redirect(url_for('auth.two_factor_auth')), 200


@auth.route('/profile/remove2fa', methods=['GET'])
@login_required
def remove_2fa():
    current_user.remove_2fa()
    return redirect(url_for('auth.two_factor_auth'))


@auth.route('/validatetotptoken', methods=['POST'])
@login_required
def check_2fa():
    validity = current_user.verify_totp(request.get_data(as_text=True).strip())
    return str(validity), 200 if validity else 204


@auth.route('/reset', methods=['GET', 'POST'])
@login_pointless
def reset_request():
    if request.method == 'GET':
        return render_template('auth/reset/reset_request.html')
    elif request.method == 'POST':
        email = request.form.get('email')
        user: User = User.query.filter_by(email=email).first()

        if not user:
            flash(f'User with E-Mail {email} was not found!', 'error')
            return redirect(url_for('auth.reset_request'))

        prr: PasswordResetRequest = PasswordResetRequest.query.order_by(
            PasswordResetRequest.created_at.desc()).filter_by(
            user_id=user.id).first()

        if prr and prr.is_request_still_valid and not prr.is_request_used:
            flash(f'A reset form has already been sent to your E-Mail!',
                  'error')
            return redirect(url_for('auth.reset_request'))

        prr = PasswordResetRequest(requested_by=request.remote_addr,
                                   user_id=user.id)
        db.session.add(prr)
        db.session.commit()

        msg = Message()
        msg.subject = 'Password Reset'
        msg.recipients = [user.email]
        msg.sender = config.Config.MAIL_USERNAME
        msg.html = render_template('emails/reset_password.html', **{
            'prr': prr
        })

        mail.send(msg)

        flash(f'A reset form has been sent to your E-Mail!', 'success')
        return redirect(url_for('auth.reset_request'))


@auth.route('/reset/<token>', methods=['GET', 'POST'])
@login_pointless
def reset(token):
    try:
        prr: [PasswordResetRequest, None] = PasswordResetRequest.query.filter_by(
            id=token).order_by(PasswordResetRequest.created_at.desc()).first()
    except StatementError:
        prr = None

    if not prr:
        flash(f'Password request token "{token}" is incorrect!', 'error')
        return redirect(url_for('auth.login'))

    if prr.is_request_used:
        flash(f'Password request token "{token}" is already used!', 'error')
        return redirect(url_for('auth.login'))

    if not prr.is_request_still_valid:
        flash(f'Password request token "{token}" is not valid anymore!',
              'error')
        return redirect(url_for('auth.login'))

    if request.method == 'GET':
        return render_template('auth/reset/reset.html')
    elif request.method == 'POST':
        new_password = request.form.get('newpassword')

        if not Validators.password(new_password):
            flash(
                'New password is not valid! The password should contain between 8 to 128 characters from the '
                'following: (a-z, A-Z, 0-9, ~!@#$%^&*()_+-=)',
                'error')
            return redirect(url_for('auth.reset', token=token))

        prr.user.password = new_password
        prr.used_by = request.remote_addr
        db.session.commit()

        flash('Successfully changed password!', 'success')
        return redirect(url_for('auth.login'))


@auth.route('/getkey')
@login_required
def test_getkey():
    f = get_fernet(session['my_key'])
    k = f.decrypt(current_user.second_encryption_key)
    # out = ''
    # for b in k:
    #     out += f'{hex(b).upper()[2:]} '

    return k


#################
#               #
#     VIEWS     #
#               #
#################
def make_tree(path):
    tree = dict(name=path, children=[])
    try:
        lst = os.listdir(path)
    except OSError:
        pass  # ignore errors
    else:
        for name in lst:
            fn = os.path.join(path, name)
            if os.path.isdir(fn):
                tree['children'].append(make_tree(fn))
            else:
                tree['children'].append(dict(name=fn))
    return tree


@view.route('/')
def index():
    if current_user.is_authenticated and not current_user.has_2fa:
        flash('You should enable 2FA in your profile settings :)', 'warn')

    return render_template('index.html')


@view.route('/upload', methods=['POST'])
@login_required
def upload():
    from . import app

    files = request.files.getlist('file')

    first_key = session['my_key']
    first_fernet = get_fernet(first_key)

    file_encryption_key = first_fernet.decrypt(current_user.second_encryption_key)

    def mkdirs(p: Path):
        if p.parent and not p.parent.exists():
            mkdirs(p.parent)
        p.mkdir(exist_ok=True)

    for file in files:
        file: FileStorage

        path: Path = current_user.folder / file.filename
        mkdirs(path.parent)

        userfile: UserFile = UserFile(owner=current_user, relative_path=str(path.relative_to(Path(app.root_path) / 'web/uploads' / str(current_user.id))))
        print(userfile)

        with path.open('wb') as f:
            while chunk := file.stream.read(8096):
                f.write(chunk)

    return 'OK'


@view.route('/defaultprofilepicture')
def _dpp():
    return redirect(config.Config.DEFAULT_PROFILE_PICTURE)

#################
#               #
#    STORAGE    #
#               #
#################
