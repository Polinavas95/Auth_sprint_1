from collections.abc import Callable
from functools import wraps
from typing import ParamSpec, cast

from flask import Response, make_response, redirect, request, url_for
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_jwt,
    set_access_cookies,
    set_refresh_cookies,
    unset_jwt_cookies,
    verify_jwt_in_request,
)
from flask_jwt_extended.exceptions import JWTExtendedException
from loguru import logger

from src.core.models import User
from src.db.redis import jwt_redis_blocklist

jwt = JWTManager()
P = ParamSpec('P')


def roles_required(
    *roles: str,
) -> Callable[[Callable[P, Response]], Callable[P, Response]]:
    """Параметризованный декоратор для проверки роли пользователя

    Args:
        role (str): Роль пользователя

    Usage:
        @views.route('/admin')
        @role_required('admin')
        def admin() -> str:
            ...
    """

    def wrapper(fn: Callable[P, Response]) -> Callable[P, Response]:
        """A decorator

        Args:
            fn (Callable[P, Response]):

        Returns:
            Callable[P, Response]:
        """

        @wraps(fn)
        def decorated_view(*args: P.args, **kwargs: P.kwargs) -> Response:
            try:
                verify_jwt_in_request()
                claims = get_jwt()

                if len(roles) == 0:
                    return fn(*args, **kwargs)

                for role in claims['roles']:
                    if role in roles:
                        return fn(*args, **kwargs)
            except JWTExtendedException:
                logger.info(
                    'Failed to validate jwt and/or role.',
                )
            return cast(
                Response,
                redirect(
                    url_for('views.login', next=request.path),
                ),
            )

        return decorated_view

    return wrapper


@jwt.user_identity_loader
def user_identity_lookup(user: User) -> str:
    """Функция для извлечения идентификатора пользователя из записи в БД.
    Вызывается при вызове функции `create_access_token`.

    Args:
        user (User): Модель пользователя

    Returns:
        str: Идентификатор пользователя
    """
    return str(user.fs_uniquifier)


@jwt.user_lookup_loader
def user_lookup_callback(
    _jwt_header: dict[str, str | int], jwt_data: dict[str, str | int]
) -> User:
    """Функция для извлечения пользователя из БД по идентификатору.
    Вызывается при вызове функции `get_current_user`.

    Args:
        _jwt_header (dict[str, str  |  int]): заголовок токена
        jwt_data (dict[str, str  |  int]): payload токена

    Returns:
        User: Объект пользователя
    """

    identity = jwt_data['sub']
    return cast(User, User.get(fs_uniquifier=identity))   # type: ignore


@jwt.unauthorized_loader
def unauthorized_callback(_msg: str) -> Response:
    """Вызывается при отсутствии токена в запросе к защищенному ресурсу.

    Args:
        _msg: str: Сообщение об ошибке

    Returns:
        Response: Ответ браузеру
    """
    logger.info('Unauthorized access: {msg}', msg=_msg)
    return cast(
        Response,
        redirect(
            url_for('views.login', next=request.path),
        ),
    )


@jwt.invalid_token_loader
def token_verification_failed_callback(_msg: str) -> Response:
    """Вызывается при невалидном токене.

    Args:
        _msg (str): Сообщение об ошибке

    Returns:
        Response: Ответ браузеру
    """
    logger.info('TOKEN VERIFICATION FAILED {msg}', msg=_msg)
    logger.info(request.path)
    response = make_response(
        redirect(url_for('views.login', next=request.path)), 302
    )
    unset_jwt_cookies(response)
    return response


@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(
    _jwt_header: dict[str, str | int], jwt_payload: dict[str, str | int]
) -> bool:
    """Проверяет, отозван ли токен.
    Вызывается при каждом обращении к защищенному ресурсу.

    Args:
        _jwt_header (dict[str, str  |  int]): заголовок токена
        jwt_payload (dict[str, str  |  int]): payload токена

    Returns:
        bool: True, если токен отозван, иначе False
    """

    token_identifier = str(jwt_payload['jti'])
    user_identifier = str(jwt_payload['sub'])
    token_init_time = int(jwt_payload['iat'])
    is_revoked = jwt_redis_blocklist.is_token_revoked(
        token_identifier, user_identifier, token_init_time
    )
    logger.info('Token is revoked: {is_revoked}', is_revoked=is_revoked)
    return is_revoked


def revoke_token(encoded_token: str) -> bool:
    """Отзывает токен.

    Args:
        encoded_token (str): Закодированный (сырой) токен.

    Returns:
        bool: True, если токен отозван, иначе False
    """
    payload = decode_token(encoded_token)
    token_identifier = str(payload['jti'])
    token_expiration_time = int(payload['exp'])
    return jwt_redis_blocklist.revoke_token(
        token_identifier, token_expiration_time
    )


def revoke_all_user_tokens(user: User) -> bool:
    """Отзывает все токены пользователя, активные до текущего момента.

    Args:
        user (User): Объект пользователя

    Returns:
        bool: True, если токены отозваны, иначе False
    """
    return jwt_redis_blocklist.revoke_all_user_tokens(str(user.fs_uniquifier))


@jwt.revoked_token_loader
def revoked_token_callback(
    _jwt_header: dict[str, str | int], _jwt_data: dict[str, str | int]
) -> Response:
    """Вызывается при обращении к защищенному ресурсу с отозванным токеном.

    Args:
        _jwt_header (dict[str, str  |  int]): заголовок токена
        _jwt_data (dict[str, str  |  int]): payload токена

    Returns:
        Response: Ответ браузеру
    """
    response = make_response(
        redirect(
            url_for('views.login', next=request.path),
        ),
        302,
    )
    unset_jwt_cookies(response)
    return response


@jwt.expired_token_loader
def expired_token_callback(
    _jwt_header: dict[str, str | int], jwt_data: dict[str, str | int]
) -> Response:
    """Вызывается при истечении срока действия одного из токенов.

    При истечении срока действия refresh токена, происходит редирект на
    страницу логина.

    При истечении срока действия access токена, происходит редирект на
    /refresh и затем на искомую страницу.

    Args:
        _jwt_header (dict[str, str  |  int]): заголовок токена
        jwt_data (dict[str, str  |  int]): payload токена

    Returns:
        Response: Ответ браузеру
    """
    logger.info('TOKEN EXPIRED')
    logger.info(request.path)
    logger.info(jwt_data)
    token_type = jwt_data['type']

    if token_type == 'refresh':   # noqa
        return cast(
            Response,
            redirect(
                url_for('views.login', next=request.path),
            ),
        )
    refresh_token = request.cookies.get('refresh_token_cookie')
    if not refresh_token:
        return cast(
            Response,
            redirect(
                url_for('views.login', next=request.path),
            ),
        )

    return cast(
        Response,
        redirect(
            url_for('views.refresh', next=request.path),
        ),
    )


def create_token_pair(user: User) -> tuple[str, str]:
    """Создание закодированной пары токенов

    Args:
        user (User): Пользователь

    Returns:
        tuple[str, str]: Пара токенов
    """
    access_token = create_access_token(
        identity=user,
        additional_claims={
            'roles': [role.name for role in user.roles]  # type: ignore
        },
    )
    refresh_token = create_refresh_token(identity=user)
    return access_token, refresh_token


def set_token_cookies(
    response: Response,
    access_token: str | None,
    refresh_token: str | None,
    remember: bool = False,
) -> Response:
    """Установка токенов в куки

    Args:
        response (Response): Ответ сервера
        access_token (str | None): Токен доступа
        refresh_token (str | None): Токен обновления
        remember (bool, optional): Запомнить пользователя. Defaults to False.
    Returns:
        Response: Ответ сервера
    """
    cookie_max_age = 31540000 if remember else None   # 1 year
    if access_token:
        set_access_cookies(response, access_token, cookie_max_age)
    if refresh_token:
        set_refresh_cookies(
            response, refresh_token, cookie_max_age  # type: ignore
        )
    return response
