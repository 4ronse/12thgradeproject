import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from typing import Union


def get_encryption_key(mat: Union[str, bytes], salt: Union[str, bytes]) -> bytes:
    if type(mat) == str: mat = mat.encode()
    if type(salt) == str: salt = salt.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(mat))


def get_fernet(key: Union[bytes, str]) -> Fernet:
    if type(key) == str: key = key.encode()
    return Fernet(key)
