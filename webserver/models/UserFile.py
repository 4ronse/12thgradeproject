import os

from .Base import BaseUserRelatedModel, GUID
from .. import db
from hashlib import sha256


class UserFile(BaseUserRelatedModel):
    __tablename__ = "userfiles"

    owner = db.Column(GUID(), db.ForeignKey('users.id'), nullable=False)
    relative_to_upload_dir_path = db.Column(db.String, nullable=False)
    key = db.Column(db.String, nullable=False)
    salt = db.Column(db.String, nullable=False)
    real_name = db.Column(db.String, nullable=False, unique=True)
    hashed_name = db.Column(db.String(256), nullable=False)
