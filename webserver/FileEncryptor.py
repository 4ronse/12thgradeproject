import os

from cryptography.fernet import Fernet

from . import app
from .models.User import User
from .models.UserFile import UserFile

from werkzeug.datastructures import FileStorage
from pathlib import Path

"""
def upload():
    from . import app

    files = request.files.getlist('file')

    first_key = session['my_key']
    first_fernet = get_fernet(first_key)

    file_encryption_key = first_fernet.decrypt(current_user.second_encryption_key)

    def mkdirs(p: Path):
        if p.parent and not p.parent.exists():
            mkdirs(p.parent)
        p.mkdir(exist_ok=True)

    for file in files:
        file: FileStorage

        path: Path = current_user.folder / file.filename
        mkdirs(path.parent)

        userfile: UserFile = UserFile(owner=current_user, relative_path=str(path.relative_to(Path(app.root_path) / 'web/uploads' / str(current_user.id))))
        print(userfile)

        with path.open('wb') as f:
            while chunk := file.stream.read(8096):
                f.write(chunk)

    return 'OK'
"""


def mkdirs(p: Path):
    if p.parent and not p.parent.exists():
        mkdirs(p.parent)
    p.mkdir(exist_ok=True)


class FileEncryptor:
    @staticmethod
    def encrypt_file(user: User, file: FileStorage, fernet: Fernet):
        out_path = Path(app.root_path) / 'web/uploads' / str(user.id) / file.filename
        rtud = out_path.relative_to(app.config['UPLOAD_PATH'])  # Relative To Upload Path
        salt = os.urandom(512)
        mkdirs(out_path.parent)

        with out_path.open('wb') as out:
            out.write(fernet.encrypt(file.stream.read(8096)))

        return rtud, salt

    def decrypt_file(self, key: bytes, file: UserFile):
        pass
