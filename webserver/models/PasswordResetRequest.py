from datetime import datetime, timedelta
from flask import url_for
from .Base import BaseUserRelatedModel, GUID
from .User import User
from .. import db


class PasswordResetRequest(BaseUserRelatedModel):
    __tablename__ = 'passwordresetrequests'
    requested_by = db.Column(db.String, nullable=True)
    used_by = db.Column(db.String, nullable=True)
    ttl = db.Column(db.Integer, nullable=False, default=600)  # 600s = 10m
    user_id = db.Column(GUID(), db.ForeignKey('users.id'), nullable=False)

    @property
    def user(self) -> User:
        return User.query.filter_by(id=self.user_id).first()

    @property
    def link(self) -> str:
        return url_for('auth.reset', _external=True, token=self.id)

    @property
    def is_request_still_valid(self) -> bool:
        return datetime.utcnow() < self.created_at + timedelta(
            seconds=self.ttl)

    @property
    def is_request_used(self) -> bool:
        return self.used_by is not None

    def __repr__(self):
        return f'PasswordResetRequest[ID: {self.id}; created_at: {self.created_at}; updated_at: {self.updated_at}; requested_by: {self.requested_by}; used_by: {self.used_by}; ttl: {self.ttl}; user: {self.user}; is_valid: {self.is_request_still_valid}; is_used: {self.is_request_used}]'
