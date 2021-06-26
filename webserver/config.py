from dotenv import load_dotenv
from pathlib import Path
from os import getenv

dotenv_path = Path('..') / '.env'

load_dotenv(dotenv_path=dotenv_path)


class Config:
    DEBUG = getenv('NO_SSL', 'False') == 'True'
    PROJECT_NAME = getenv('PROJECT_NAME', 'DaCrate')
    SECRET_KEY = getenv('SECRET_KEY', '38m9n740fgv529e08m,7345kjg6sz9870m3,2jn4k5wgvz')  # Randomly bashed my hands on keyboard
    NO_SSL = getenv('NO_SSL', 'False') == 'True'
    DEFAULT_PROFILE_PICTURE = getenv('DEFAULT_PROFILE_PICTURE')

    HOST = getenv('HOST', '0.0.0.0')
    PORT_SSL = getenv('PORT_SSL', 443)
    PORT_NO_SSL = getenv('PORT_NO_SSL', 80)

    MAIL_SERVER = getenv('MAIL_SERVER')
    MAIL_PORT = getenv('MAIL_PORT')
    MAIL_USE_SSL = getenv('MAIL_USE_SSL')
    MAIL_USERNAME = getenv('MAIL_USERNAME')
    MAIL_PASSWORD = getenv('MAIL_PASSWORD')

    UPLOAD_PATH = getenv('UPLOAD_PATH', None)
    TEMP_PATH = getenv('TEMP_PATH', None)
