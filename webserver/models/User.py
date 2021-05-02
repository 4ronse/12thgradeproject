import base64
import os
import onetimepass

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
import cryptography.hazmat.primitives.asymmetric.padding as padding

from pathlib import Path
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from .Base import BaseUserRelatedModel
from .. import db, app
from ..config import Config
from ..utils.encryptionutils import get_encryption_key, get_fernet

from typing import Union


class User(UserMixin, BaseUserRelatedModel):
    __tablename__ = 'users'

    email = db.Column(db.String(100), unique=True)
    name = db.Column(db.String, nullable=False)
    _password = db.Column('password', db.String(64), nullable=False)
    profile_picture = db.Column(db.String,
                                nullable=True,
                                default=Config.DEFAULT_PROFILE_PICTURE)

    otp_secret = db.Column(db.String(16), nullable=True)

    helper_key_salt = db.Column(db.String, nullable=False)

    rsa_public_key = db.Column(db.String, nullable=False)
    rsa_private_key = db.Column(db.String, nullable=False)
    rsa_decryption_key = db.Column(db.String, nullable=False)

    files = db.relationship('UserFile', backref='users', lazy=True)

    def __init__(self, password: str, *args, **kwargs):
        """
        TODO:
            Perhaps change encryption to be PBKDF2 AND RSA for files.
            Might be smarter :ok-hand:
        """
        super(User, self).__init__(*args, **kwargs)

        self.helper_key_salt = salt = os.urandom(512)
        fernet = get_fernet(get_encryption_key(password, salt))

        rsa_decryption_key_mat = os.urandom(512)
        rsa_decryption_key_salt = os.urandom(512)

        rsa_decryption_key = get_encryption_key(rsa_decryption_key_mat, rsa_decryption_key_salt)
        self.rsa_decryption_key = fernet.encrypt(rsa_decryption_key)

        rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )

        private_pem, public_pem = rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ), rsa_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        fernet = get_fernet(rsa_decryption_key)

        self.rsa_private_key = fernet.encrypt(private_pem)
        self.rsa_public_key = public_pem

        self.password = password

        if not self.folder.exists():
            # Ideally mode shouldn't be 0o777 but whatever, that's just a school project
            self.folder.mkdir(True)

    def _generate_rsa_key_pair(self):
        pass

    def get_password_based_pbkdf2_encryption_key(self, password: str) -> bytes:
        password = password.encode()
        return get_encryption_key(password, self.helper_key_salt)

    def generate_otp_secret(self) -> str:
        """ Method will generate a random OTP token and also commits changes to database

        Returns:
            str: The OTP token
        """
        self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
        db.session.commit()
        return self.otp_secret

    def remove_2fa(self):
        """ Method sets user's OTP token to None and commits to database """
        self.otp_secret = None
        db.session.commit()

    def get_totp_uri(self) -> str:
        """ Method creates a formated TOTP uri

        Returns:
            str: TOTP uri
        """
        return 'otpauth://totp/{project_name}:{username}?secret={otp_secret}&issuer={project_name}' \
            .format(project_name=Config.PROJECT_NAME, username=self.email, otp_secret=self.otp_secret)

    def verify_totp(self, token: str) -> bool:
        """ Method verefies TOTP token

        Args:
            token (str): TOTP token

        Returns:
            bool: Is token valid
        """
        return onetimepass.valid_totp(token, self.otp_secret)

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute')

    @password.setter
    def password(self, password: str):
        # self._generate_new_encryption_key(override=True)
        self._password = generate_password_hash(password=password,
                                                method='sha256')

    @property
    def has_2fa(self) -> bool:
        return self.otp_secret is not None

    def validate_password(self, password) -> bool:
        return check_password_hash(self._password, password)

    def get_private_rsa_pem(self, helper_key: bytes) -> bytes:
        fernet = get_fernet(helper_key)
        fernet = get_fernet(fernet.decrypt(self.rsa_decryption_key))
        return fernet.decrypt(self.rsa_private_key)

    @property
    def folder(self) -> Path:
        def mkdirs(p: Path):
            if p.parent and not p.parent.exists():
                mkdirs(p.parent)
            p.mkdir()

        path = Path(app.config['UPLOAD_PATH']) / f'{self.id}'
        if not path.exists():
            # Ideally mode shouldn't be 0o777 but whatever, that's just a school project
            mkdirs(path)
        return path

    def __repr__(self):
        return f"User[ID: {self.id}; Name: {self.name}; E-Mail: {self.email}; Has2FAEnabled: {self.has_2fa}]"

    def delete(self):
        pass
