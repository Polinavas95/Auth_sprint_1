import hashlib
import secrets

from src.core.config import APP_CONFIG, SALT_LENGTH
from src.core.models import User


def generate_salt(length: int = SALT_LENGTH) -> str:
    """Генерирует криптоустойчивую строку заданной длины

    Args:
        length (int, optional): Длина строки. Defaults to SALT_LENGTH.

    Returns:
        str: Случайная строка
    """
    return secrets.token_urlsafe(length)


def hash_password(
    password: str,
    salt: str | None,
    iterations: int = 100000,
    hash_name: str = 'sha256',
) -> str:
    """Хеширует пароль используя алгоритм PBKDF2

    Args:
        password (str): Пароль
        salt (str | None): Соль
        iterations (int, optional): Количество итераций. Defaults to 100000.
        hash_name (str, optional): Имя алгоритма хеширования.
            Defaults to 'sha256'.

    Returns:
        str: Хеш пароля
    """
    pepper = APP_CONFIG['SECRET_KEY']
    salt_pepper = f'{salt}{pepper}'.encode()
    digest = hashlib.pbkdf2_hmac(
        hash_name, password.encode(), salt_pepper, iterations
    )
    return digest.hex()


def check_password(
    user: User,
    password: str,
    iterations: int = 100000,
    hash_name: str = 'sha256',
) -> bool:
    """Проверяет введённый пароль с хешем пароля пользователя в БД

    Args:
        user (User): Пользователь
        password (str): Пароль
        iterations (int, optional): Количество итераций. Defaults to 100000.
        hash_name (str, optional): Имя алгоритма хеширования.
            Defaults to 'sha256'.

    Returns:
        bool: True если пароли совпадают, иначе False
    """
    password_hash = str(user.password_hash)
    salt = str(user.fs_uniquifier)

    return password_hash == hash_password(
        password,
        salt,
        iterations,
        hash_name,
    )
