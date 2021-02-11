import base64
import os
import onetimepass

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from .Base import BaseUserRelatedModel 
from .. import db
from ..config import Config

class User(UserMixin, BaseUserRelatedModel):
    __tablename__ = 'users'
    email = db.Column(db.String(100), unique=True)
    name = db.Column(db.String, nullable=False)
    _password = db.Column('password', db.String(64), nullable=False)
    profile_picture = db.Column(db.String, nullable=True, default=Config.DEFAULT_PROFILE_PICTURE)
    otp_secret = db.Column(db.String(16), nullable=True)

    def generate_otp_secret(self) -> str:
        self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
        db.session.commit()
        return self.otp_secret

    def remove_2fa(self):
        self.otp_secret = None
        db.session.commit()

    def get_totp_uri(self):
        return 'otpauth://totp/{project_name}:{username}?secret={otp_secret}&issuer={project_name}' \
            .format(project_name=Config.PROJECT_NAME, username=self.id, otp_secret=self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute')

    @password.setter
    def password(self, password):
        self._password = generate_password_hash(password=password, method='sha256')

    @property
    def has_2fa(self) -> bool:
        return self.otp_secret is not None

    def validate_password(self, password) -> bool:
        return check_password_hash(self._password, password)

    def __repr__(self):
        return f"User[ID: {self.id}; Name: {self.name}; E-Mail: {self.email}; PasswordHash: {self.password}]"