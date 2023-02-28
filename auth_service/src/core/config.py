import datetime
import os
from distutils.util import strtobool
from secrets import token_urlsafe

import dotenv
from pydantic import BaseModel

dotenv.load_dotenv()


class PostgresConfig(BaseModel):
    database: str | None = None
    user: str | None = None
    password: str | None = None
    host: str | None = None
    port: int | None = None


class RedisConfig(BaseModel):
    host: str | None = None
    port: int | None = None
    db: int | None = None
    password: str | None = None
    decode_responses: bool = True


POSTGRES_CONFIG = PostgresConfig(
    database=os.environ.get('POSTGRES_DB', 'users_database'),
    user=os.environ.get('POSTGRES_USER', 'app'),
    password=os.environ.get('POSTGRES_PASSWORD', '123qwe'),
    host=os.environ.get('POSTGRES_HOST', 'postgres'),
    port=int(os.environ.get('POSTGRES_PORT', 5432)),
)

REDIS_CONFIG = RedisConfig(
    host=os.environ.get('REDIS_HOST', 'redis'),
    port=int(os.environ.get('REDIS_PORT', 6379)),
    db=int(os.environ.get('REDIS_DB', 0)),
    password=os.environ.get('REDIS_PASSWORD', ''),
)

SALT_LENGTH = 16
DEBUG = os.environ.get('DEBUG', 'True') == 'True'
APP_HOST = os.environ.get('APP_HOST', '0.0.0.0')   # noqa
APP_PORT = int(os.environ.get('APP_PORT', 5000))


APP_CONFIG = {
    'SECRET_KEY': os.getenv('SECRET_KEY', token_urlsafe(SALT_LENGTH)),
    'JWT_SECRET_KEY': os.getenv('SECRET_KEY', token_urlsafe(SALT_LENGTH)),
    'JWT_TOKEN_LOCATION': ['cookies'],
    'JWT_ACCESS_TOKEN_EXPIRES': datetime.timedelta(hours=12),
    'JWT_COOKIE_SECURE': False,  # set to True in production
    'JWT_REFRESH_TOKEN_EXPIRES': datetime.timedelta(days=10),
    'JWT_COOKIE_CSRF_PROTECT': False,
    'JWT_SESSION_COOKIE': True,
    'JWT_JSON_KEY': os.getenv('JWT_JSON_KEY', 'access_token'),
    'JWT_REFRESH_JSON_KEY': os.getenv('JWT_REFRESH_JSON_KEY', 'refresh_token'),
    'WTF_CSRF_ENABLED': strtobool(
        os.getenv('WTF_CSRF_ENABLED', 'false')
    ),  # set to True in production
    'DEBUG': True,
}
