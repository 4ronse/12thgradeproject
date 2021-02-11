import re

from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import Blueprint, request, render_template, redirect, url_for, flash
from flask.wrappers import Response
from flask_login import current_user, login_user, logout_user, login_required
from .models.Base import UUID
from .models.User import User
from . import db, config

view = Blueprint('view', __name__)
auth = Blueprint('auth', __name__)

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
        return re.search(r"^([a-zA-Z]{2,}\s[a-zA-Z]{1,}'?-?[a-zA-Z]{2,}\s?([a-zA-Z]{1,})?)$", val)

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

        user = User.query.filter_by(email=email).first()

        if not user:
            flash('User not found!', 'error')
            return redirect(url_for('auth.login'))
        
        if not check_password_hash(user.password, password):
            flash('Password incorrect!', 'error')
            return redirect(url_for('auth.login'))

        login_user(user, remember=remember)

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
            errors.append('Password is not valid! The password should contain between 8 to 128 characters from the following: (a-z, A-Z, 0-9, ~!@#$%^&*()_+-=)')
        
        if not Validators.name(name):
            errors.append('Name is not valid!')
        

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth/register.html')

        user = User.query.filter_by(email=email).first()

        if user:
            flash('User with email {} already exists'.format(email), 'error')
            return redirect(url_for('auth.register'))

        user = User(email=email, password=generate_password_hash(password, method='sha256'), name=name, profile_picture=profile_picture)
        print(user.profile_picture)
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
        email = request.form.get('email')
        profile_picture = request.form.get('profilepic')
        name = request.form.get('name')

        errors = []

        if not Validators.email(email):
            errors.append('E-Mail is not valid!')

        if not Validators.name(name):
            errors.append('Name is not valid!')
        

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth/profile.html')

        if current_user.email != email:
            user = User.query.filter_by(email=email).first()
            if user:
                flash('User with email {} already exists'.format(email), 'error')
                return redirect(url_for('auth.profile'))

        current_user.name = name
        current_user.email = email
        current_user.profile_picture = profile_picture

        db.session.commit()

        flash(f'Successfully commited changes!', 'success')
        return redirect(url_for('auth.profile'))
    else:
        return render_template('auth/profile.html')
        

#################
#               #
#     VIEWS     #
#               #
#################
@view.route('/')
@view.route('/index')
def index():
    return render_template('index.html')

@view.route('/defaultprofilepicture')
def _dpp():
    return redirect(config.Config.DEFAULT_PROFILE_PICTURE)

@view.route('/user/<uuid>')
def user(uuid):
    return str(User.query.get(uuid))

