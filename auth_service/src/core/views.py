from collections.abc import Callable
from typing import Any

from flask import Blueprint, request
from flask_jwt_extended import get_current_user, verify_jwt_in_request
from flask_wtf.csrf import generate_csrf  # type: ignore
from loguru import logger

from src.core.controllers import (
    HistoryController,
    IndexController,
    LoginChangeController,
    LoginController,
    LogoutAllController,
    LogoutController,
    PasswordChangeController,
    ProfileController,
    RefreshController,
    RegisterController,
)
from src.core.jwt import roles_required
from src.utils.template_utils import navbar_items

views = Blueprint('views', __name__, url_prefix='/auth')


def add_route(
    rule: str,
    methods: list[str],
    endpoint: str,
    *controller_components: Callable[..., Callable[..., Any]]
) -> None:
    route_processor = controller_components[-1]()
    for decorator in controller_components[-2::-1]:
        route_processor = decorator(route_processor)
    route_processor.required_methods = methods   # type: ignore

    views.add_url_rule(
        rule,
        endpoint=endpoint,
        view_func=route_processor,
    )


add_route('/login', ['GET', 'POST'], 'login', LoginController)
add_route('/register', ['GET', 'POST'], 'register', RegisterController)
add_route(
    '/logout',
    ['POST'],
    'logout',
    roles_required('user', 'admin'),
    LogoutController,
)
add_route(
    '/logout_all',
    ['POST'],
    'logout_all',
    roles_required('user', 'admin'),
    LogoutAllController,
)
add_route(
    '/refresh',
    ['POST'],
    'refresh',
    roles_required('user', 'admin'),
    RefreshController,
)

add_route(
    '/', ['GET'], 'index', roles_required('user', 'admin'), IndexController
)
add_route(
    '/profile',
    ['GET'],
    'profile',
    roles_required('user', 'admin'),
    ProfileController,
)
add_route(
    '/history',
    ['GET'],
    'history',
    roles_required('user', 'admin'),
    HistoryController,
)
add_route(
    '/change_login',
    ['GET', 'POST'],
    'change_login',
    roles_required('user', 'admin'),
    LoginChangeController,
)
add_route(
    '/change_password',
    ['GET', 'POST'],
    'change_password',
    roles_required('user', 'admin'),
    PasswordChangeController,
)


@views.context_processor
def inject_navbar() -> dict[str, list[str]]:
    verify_jwt_in_request(optional=True)
    current_user = get_current_user()
    csrf_token = generate_csrf()

    navbar = []
    if not current_user:
        logger.info('ANONIM')
        for item in navbar_items:
            item.init()
            if 'anon' in item.roles:
                is_active = item.href == request.path
                navbar.append(item.to_html(csrf_token, is_active))
        return {'navbar_items': navbar}
    logger.info('AUTHORIZED')
    for item in navbar_items:
        item.init()
        for role in current_user.roles:
            if role.name in item.roles:
                is_active = item.href == request.path
                navbar.append(item.to_html(csrf_token, is_active))
    return {'navbar_items': navbar}
