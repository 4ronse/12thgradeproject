import os

from .Base import BaseUserRelatedModel, GUID
from .. import db


class UserFile(BaseUserRelatedModel):
    __tablename__ = "userfiles"

    owner = db.Column(GUID, db.ForeignKey('users.id'), nullable=False)
    relative_to_upload_dir_path = db.Column(db.String, nullable=False)
    salt = db.Column(db.String, nullable=False)

    def __init__(self, salt: bytes = None, *args, **kwargs):
        if not salt:
            salt = os.urandom(512)
            
        super(UserFile, self).__init__(salt=salt, *args, **kwargs)

    def __repr__(self):
        return f'UserFile[Owner: {self.owner.id}; salt: {len(self.salt)}; Path: `{self.relative_path}`]'
