from typing import Union

from flask import Flask, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_session import Session
from flask_socketio import SocketIO

from .config import Config

from pathlib import Path

db = SQLAlchemy()
mail = Mail()
socketio = SocketIO(manage_session=False)
app: Flask = None


def create_app(*args, **kwargs):
    """ Creates Flask object """
    global app

    webserver_folder = Path(__file__).parent
    cert_path = webserver_folder / 'cert.pem'
    key_path = webserver_folder / 'key.pem'
    ssl_context = (str(cert_path.absolute()), str(key_path.absolute()))

    app = Flask(__name__,
                static_folder="web/static",
                template_folder="web/templates")

    app.config['SESSION_TYPE'] = 'filesystem'

    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

    app.debug = Config.DEBUG
    app.config['SECRET_KEY'] = Config.SECRET_KEY
    app.config['PROJECT_NAME'] = Config.PROJECT_NAME
    app.config['DEFAULT_PROFILE_PICTURE'] = Config.DEFAULT_PROFILE_PICTURE

    app.config['MAIL_SERVER'] = Config.MAIL_SERVER
    app.config['MAIL_PORT'] = Config.MAIL_PORT
    app.config['MAIL_USE_SSL'] = Config.MAIL_USE_SSL
    app.config['MAIL_USERNAME'] = Config.MAIL_USERNAME
    app.config['MAIL_PASSWORD'] = Config.MAIL_PASSWORD

    if not Config.UPLOAD_PATH:
        app.config['UPLOAD_PATH'] = Path(app.root_path) / 'uploads/'
    elif Path(Config.UPLOAD_PATH).is_absolute():
        app.config['UPLOAD_PATH'] = Config.UPLOAD_PATH
    else:
        app.config['UPLOAD_PATH'] = Path(app.root_path) / Config.UPLOAD_PATH

    if not Config.TEMP_PATH:
        app.config['TEMP_PATH'] = Path(app.root_path) / 'temp/'
    elif Path(Config.UPLOAD_PATH).is_absolute():
        app.config['TEMP_PATH'] = Config.TEMP_PATH
    else:
        app.config['TEMP_PATH'] = Path(app.root_path) / Config.TEMP_PATH

    db.init_app(app)
    mail.init_app(app)
    Session(app)
    socketio.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    from .models.User import User

    @login_manager.user_loader
    def load_user(user_id) -> User:
        return User.query.get(user_id)

    from .routes import view as view_blueprint
    from .routes import auth as auth_blueprint
    from .routes import storage as storage_blueprint

    app.register_blueprint(view_blueprint)
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(storage_blueprint)

    from . import wsroutes

    socketio.run(app, debug=True, ssl_context=ssl_context, *args, **kwargs)
    # return lambda *args, **kwargs: smart_ass(*args, **kwargs)
