from flask_login import UserMixin
from werkzeug.security import generate_password_hash
from .Base import BaseUserRelatedModel 
from .. import db
from ..config import Config

class User(UserMixin, BaseUserRelatedModel):
    __tablename__ = 'users'
    email = db.Column(db.String(100), unique=True)
    name = db.Column(db.String, nullable=False)
    password = db.Column(db.String(64), nullable=False)
    profile_picture = db.Column(db.String, nullable=True, default=Config.DEFAULT_PROFILE_PICTURE)

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password = generate_password_hash(password=password, method='sha256')

    def __repr__(self):
        return f"User[ID: {self.id}; Name: {self.name}; E-Mail: {self.email}; PasswordHash: {self.password}]"