import os

import dotenv
from pydantic import BaseSettings

dotenv.load_dotenv()


class TestSettings(BaseSettings):
    base_api: str = os.environ.get('BASE_API', 'http://127.0.0.1:5000')

    redis_host: str = os.environ.get('REDIS_HOST', 'redis')
    redis_port: int = os.environ.get('REDIS_PORT', 6379)
    redis_db: int = os.environ.get('REDIS_DB', 0)
    redis_password: str = os.environ.get('REDIS_PASSWORD', '')
