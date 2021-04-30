from flask import Flask, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail

from .config import Config

db = SQLAlchemy()
mail = Mail()
app: Flask = None


def create_app() -> Flask:
    """ Creates Flask object """
    global app

    app = Flask(__name__,
                static_folder="web/static",
                template_folder="web/templates")

    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

    app.config['DEBUG'] = Config.DEBUG
    app.config['SECRET_KEY'] = Config.SECRET_KEY
    app.config['PROJECT_NAME'] = Config.PROJECT_NAME
    app.config['DEFAULT_PROFILE_PICTURE'] = Config.DEFAULT_PROFILE_PICTURE
    app.config['UPLOAD_PATH'] = Config.UPLOAD_PATH or 'uploads/'

    app.config['MAIL_SERVER'] = Config.MAIL_SERVER
    app.config['MAIL_PORT'] = Config.MAIL_PORT
    app.config['MAIL_USE_SSL'] = Config.MAIL_USE_SSL
    app.config['MAIL_USERNAME'] = Config.MAIL_USERNAME
    app.config['MAIL_PASSWORD'] = Config.MAIL_PASSWORD

    db.init_app(app)
    mail.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    from .models.User import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(user_id)

    from .routes import view as view_blueprint
    from .routes import auth as auth_blueprint
    from .routes import storage as storage_blueprint

    app.register_blueprint(view_blueprint)
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(storage_blueprint)

    return app


if __name__ == '__main__':
    create_app()
    app.run(host='0.0.0.0', port=8080, debug=1)
