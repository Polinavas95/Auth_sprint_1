from abc import abstractmethod
from typing import cast

from flask import (
    Request,
    Response,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_jwt_extended import get_current_user, unset_jwt_cookies
from flask_peewee.utils import object_list  # type: ignore

from src.core.jwt import (
    create_token_pair,
    revoke_all_user_tokens,
    revoke_token,
    set_token_cookies,
)
from src.core.models import LoginEvent, User
from src.core.security import check_password, generate_salt, hash_password
from src.db.datastore import datastore


class BaseController:
    @abstractmethod
    def get(self, request: Request) -> Response:
        pass

    @abstractmethod
    def post(self, request: Request) -> Response:
        pass

    def __call__(self) -> Response:
        if request.method == 'GET':
            return self.get(request)
        return self.post(request)

    @property
    def __name__(self) -> str:
        return str(self.__class__.__name__)


class LoginController(BaseController):
    def get(self, request: Request) -> Response:
        next_url = request.args.get('next', url_for('views.index'))
        return make_response(
            render_template(
                'security/login_user.html',
                next_url=url_for('views.login', next=next_url),
            ),
            200,
        )

    def get_login_data(self, request: Request) -> dict[str, str | bool] | None:

        if request.is_json:
            data = request.get_json()
        elif request.form:
            data = request.form or {}
        email = data.get('email', None)
        password = data.get('password', None)
        remember_me = data.get('remember', False)
        if not email or not password:
            return None
        return {
            'email': email,
            'password': password,
            'remember_me': remember_me,
        }

    def post(self, request: Request) -> Response:
        login_data = self.get_login_data(request)

        if not login_data:
            error_msg = 'Enter the username and the password'
            return make_response(
                render_template(
                    'security/login_user.html', error_msg=error_msg
                ),
                401,
            )

        user = datastore.find_user(email=login_data['email'])

        if not user or not check_password(user, login_data['password']):
            error_msg = 'Wrong username or password'
            return make_response(
                render_template(
                    'security/login_user.html', error_msg=error_msg
                ),
                401,
            )

        user_agent = request.headers.get('User-Agent')

        user_history = LoginEvent(
            history=user_agent,
            user=user,
        )
        user_history.save()

        next_url = request.args.get('next', url_for('views.index'))
        response = cast(Response, redirect(next_url))

        access_token, refresh_token = create_token_pair(user)
        set_token_cookies(
            response,
            access_token,
            refresh_token,
            remember=login_data['remember_me'],
        )

        return response


class BaseChangeController(BaseController):
    request_field_name: str
    model_field_name: str
    template: str
    view_name: str

    def get_changed_data(self, request: Request) -> dict[str, str] | None:
        if request.is_json:
            data = request.get_json().get(self.request_field_name, None)
        elif request.form:
            data = request.form.get(self.request_field_name, None)
        if not data:
            return None
        return {
            self.request_field_name: data,
        }

    def set_changed_data(self, user: User, new_data: str) -> None:
        setattr(user, self.model_field_name, new_data)
        user.save()

    def get(self, _request: Request) -> Response:
        return make_response(
            render_template(
                self.template,
                next_url=url_for(self.view_name),
            ),
            200,
        )

    def post(self, request: Request) -> Response:
        changed_data = self.get_changed_data(request)
        if not changed_data:
            error_msg = f'Enter non-empty new {self.model_field_name}'
            return make_response(
                render_template(self.template, error_msg=error_msg),
                401,
            )

        new_data = changed_data[self.request_field_name]
        user = get_current_user()
        self.set_changed_data(user, new_data)

        next_url = request.args.get('next', url_for('views.index'))
        return make_response(redirect(next_url), 302)


class LoginChangeController(BaseChangeController):
    request_field_name = 'new_name'
    model_field_name = 'email'
    template = 'security/change_login.html'
    view_name = 'views.change_login'


class PasswordChangeController(BaseChangeController):
    request_field_name = 'new_password'
    model_field_name = 'password'
    template = 'security/change_password.html'
    view_name = 'views.change_password'

    def set_changed_data(self, user: User, new_password: str) -> None:
        salt = generate_salt()
        new_password_hash = hash_password(new_password, salt)
        setattr(user, self.model_field_name, new_password_hash)
        user.save()

    def post(self, request: Request) -> Response:
        response = super().post(request)

        user = get_current_user()
        revoke_all_user_tokens(user)
        unset_jwt_cookies(response)
        return response


class LogoutController(BaseController):
    def post(self, request: Request) -> Response:
        response = make_response(redirect(url_for('views.login')), 302)

        # Отзыв access токена
        if access_token := request.cookies.get('access_token_cookie'):
            revoke_token(access_token)

        # Отзыв refresh токена
        if refresh_token := request.cookies.get('refresh_token_cookie'):
            revoke_token(refresh_token)

        unset_jwt_cookies(response)
        return response


class LogoutAllController(BaseController):
    def post(self, _request: Request) -> Response:
        response = make_response(redirect(url_for('views.login')), 302)

        user = get_current_user()
        revoke_all_user_tokens(user)
        unset_jwt_cookies(response)
        return response


class RegisterController(BaseController):
    def get_register_data(self, request: Request) -> dict[str, str] | None:
        if request.is_json:
            data = request.get_json()
        elif request.form:
            data = request.form or {}

        email = data.get('email', None)
        password = data.get('password', None)

        if not email or not password:
            return None
        return {
            'email': email,
            'password': password,
        }

    def get(self, _request: Request) -> Response:
        return make_response(
            render_template('security/register_user.html'),
            200,
        )

    def post(self, request: Request) -> Response:
        register_data = self.get_register_data(request)
        if not register_data:
            error_msg = 'Enter email and password'
            return make_response(
                render_template(
                    'security/register_user.html', error_msg=error_msg
                ),
                401,
            )
        user = datastore.find_user(email=register_data['email'])
        if user:
            error_msg = 'User with this email already exists'
            return make_response(
                render_template(
                    'security/register_user.html', error_msg=error_msg
                ),
                401,
            )

        salt = generate_salt()
        password_hash = hash_password(register_data['password'], salt)

        user = datastore.create_user(
            email=register_data['email'],
            password_hash=password_hash,
            fs_uniquifier=salt,
            roles=['user'],
        )
        next_url = request.args.get('next', url_for('views.index'))
        return make_response(
            redirect(url_for('views.login', next=next_url)),
            302,
        )


class HistoryController(BaseController):
    def get(self, _request: Request) -> Response:
        user = get_current_user()
        login_events = (
            LoginEvent.select()  # type: ignore
            .where(
                LoginEvent.user == user,
            )
            .order_by(LoginEvent.registered.desc())
        )

        return make_response(
            object_list('security/history.html', login_events, paginate_by=10),
            200,
        )


class IndexController(BaseController):
    def get(self, _request: Request) -> Response:
        welcome_string = 'Welcome!'
        current_user = get_current_user()
        contex = {}
        if current_user:
            contex.update({'user': current_user})
            try:
                name = current_user.name
                email = current_user.email
                contex.update({'user_name': name})
                contex.update({'user_email': email})
                welcome_string = f'Welcome back, {current_user.name}!'
            except AttributeError:
                welcome_string = 'Welcome back!'
        contex.update({'welcome_string': welcome_string})
        return make_response(
            render_template('security/index.html', contex=contex), 200
        )


class ProfileController(BaseController):
    def get(self, _request: Request) -> Response:
        user = get_current_user()
        return make_response(
            render_template('security/profile.html', current_user=user),
            200,
        )


class RefreshController(BaseController):
    def get(self, request: Request) -> Response:
        current_user = get_current_user()
        next_url = request.args.get('next', url_for('views.index'))
        response = cast(Response, redirect(next_url, 302))

        if refresh_token := request.cookies.get('refresh_token_cookie'):
            revoke_token(refresh_token)

        access_token, refresh_token = create_token_pair(current_user)
        set_token_cookies(response, access_token, refresh_token)
        return response
