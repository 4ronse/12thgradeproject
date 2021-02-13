from dotenv import load_dotenv
from pathlib import Path
from os import getenv

dotenv_path = Path('..') / '.env'

load_dotenv(dotenv_path=dotenv_path)


class Config:
    DEBUG = getenv('DEBUG') or False
    PROJECT_NAME = getenv('PROJECT_NAME') or 'NAGDR'
    SECRET_KEY = getenv('SECRET_KEY') or \
        '38m9n740fgv529e08m,7345kjg6sz9870m3,2jn4k5wgvz'  # Randomly bashed my hands on keyboard :))
    NO_SSL = getenv('NO_SSL') or True
    DEFAULT_PROFILE_PICTURE = getenv('DEFAULT_PROFILE_PICTURE')

    MAIL_SERVER = getenv('MAIL_SERVER')
    MAIL_PORT = getenv('MAIL_PORT')
    MAIL_USE_SSL = getenv('MAIL_USE_SSL')
    MAIL_USERNAME = getenv('MAIL_USERNAME')
    MAIL_PASSWORD = getenv('MAIL_PASSWORD')