import os

from .Base import BaseUserRelatedModel, GUID
from .. import db


class FileShare(BaseUserRelatedModel):
    __tablename__ = "fileshares"

    owner = db.Column(GUID(), db.ForeignKey('users.id'), nullable=False)
    recipient = db.Column(GUID(), db.ForeignKey('users.id'), nullable=False)
    file_id = db.Column(GUID(), db.ForeignKey('userfiles.id'), nullable=False)
    encrypted_key = db.Column(db.String, nullable=False)

