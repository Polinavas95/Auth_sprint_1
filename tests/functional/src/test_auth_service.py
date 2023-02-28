from http import HTTPStatus

import pytest

from functional.settings import TestSettings

settings = TestSettings()


class BaseData:
    name = 'test'
    email = 'test3@me.com'
    password = 'password3'
    headers = {
        'Content-type': 'application/json',
        'Accept': 'text/plain',
        'Content-Encoding': 'utf-8',
    }
    signup_data = {
        'name': name,
        'email': email,
        'password': password,
    }
    l_d = {
        'email': email,
        'password': password,
    }
    l_d2 = {
        'email': email,
        'password': 'new_password',
    }
    l_d3 = {
        'email': 'newemail@mail.ru',
        'password': password,
    }
    invalid_l_d = {
        'email': email,
        'password': 'invalid',
    }
    inval_signup_data = {
        'name': name,
        'email': email,
    }
    inval2_signup_data = {
        'name': name,
        'test': email,
    }


@pytest.mark.parametrize(
    'data, status',
    [
        (BaseData.signup_data, HTTPStatus.OK),
        (BaseData.inval_signup_data, HTTPStatus.UNAUTHORIZED),
    ],
)
def test_sign_up(data, status, make_post_request):
    response = make_post_request('/auth/register', data=data)
    assert response.status_code == status


@pytest.mark.parametrize(
    'data, url, status',
    [
        (BaseData.l_d, '/auth/login', HTTPStatus.OK),
        (BaseData.invalid_l_d, '/auth/login', HTTPStatus.UNAUTHORIZED),
        (BaseData.inval_signup_data, '/auth/login', HTTPStatus.UNAUTHORIZED),
        (BaseData.inval_signup_data, '/users/login', HTTPStatus.NOT_FOUND),
    ],
)
def test_login(data, url, status, make_post_request):
    response = make_post_request(url, data)
    assert response.status_code == status


@pytest.mark.parametrize(
    'params, headers, url, status',
    [
        (BaseData.l_d, BaseData.headers, '/auth/history', HTTPStatus.OK),
        (None, BaseData.l_d, '/users/history', HTTPStatus.NOT_FOUND),
    ],
)
def test_get_history(params, headers, url, status, make_get_request):
    response = make_get_request(url, params=params, headers=headers)
    assert response.status_code == status


def test_get_index(make_get_request):
    response = make_get_request(
        '', params=BaseData.l_d, headers=BaseData.headers
    )
    assert response.status_code == HTTPStatus.OK


@pytest.mark.parametrize(
    'params, headers, url, status',
    [
        (BaseData.l_d, BaseData.headers, '/auth/profile', HTTPStatus.OK),
        (None, BaseData.l_d, '/users/profile', HTTPStatus.NOT_FOUND),
    ],
)
def test_get_user_profile(params, headers, url, status, make_get_request):
    response = make_get_request(url, params=params, headers=headers)
    assert response.status_code == status


@pytest.mark.parametrize(
    'params, headers, url, status',
    [
        (BaseData.l_d, BaseData.headers, '/auth/refresh', HTTPStatus.OK),
        (None, BaseData.l_d, '/users/refresh', HTTPStatus.NOT_FOUND),
    ],
)
def test_get_refresh_token(params, headers, url, status, make_get_request):
    response = make_get_request(url, params=params, headers=headers)
    assert response.status_code == status


def test_check_next_url(make_get_request):
    response = make_get_request(
        '/auth/refresh', params=BaseData.l_d, headers=BaseData.headers
    )
    assert response.status_code == HTTPStatus.OK
    data = 'http://127.0.0.1:5000/auth/login?next=%2Fauth%2Frefresh'
    assert response.url == data


def test_logout(make_post_request):
    response = make_post_request('/auth/login', BaseData.l_d)
    assert response.status_code == HTTPStatus.OK

    logout = make_post_request('/auth/logout', BaseData.l_d)
    assert logout.status_code == HTTPStatus.OK


def test_logout_all(make_post_request):
    response = make_post_request('/auth/login', BaseData.l_d)
    assert response.status_code == HTTPStatus.OK

    logout = make_post_request('/auth/logout_all', BaseData.l_d)
    assert logout.status_code == HTTPStatus.OK


@pytest.mark.parametrize(
    'params, headers, url, status',
    [
        (BaseData.l_d, BaseData.headers, '/auth/change_login', HTTPStatus.OK),
        (None, BaseData.l_d, '/users/change_login', HTTPStatus.NOT_FOUND),
    ],
)
def test_change_login_page(params, headers, url, status, make_get_request):
    response = make_get_request(url, params=params, headers=headers)
    assert response.status_code == status


@pytest.mark.parametrize(
    'params, headers, url, status',
    [
        (BaseData.l_d, BaseData.headers, '/auth/change_password', 200),
        (None, BaseData.l_d, '/users/change_password', HTTPStatus.NOT_FOUND),
    ],
)
def test_change_password_page(params, headers, url, status, make_get_request):
    response = make_get_request(url, params=params, headers=headers)
    assert response.status_code == status


def test_change_password(make_get_request, make_post_request):
    response = make_get_request(
        '/auth/change_password',
        params=BaseData.l_d,
        headers=BaseData.headers,
    )
    assert response.status_code == HTTPStatus.OK
    response = make_post_request('/auth/change_password', data=BaseData.l_d2)
    assert response.status_code == HTTPStatus.OK
    response = make_get_request(
        '/auth/change_password',
        params=BaseData.l_d2,
        headers=BaseData.headers,
    )
    assert response.status_code == HTTPStatus.OK


def test_change_login(make_get_request, make_post_request):
    response = make_get_request(
        '/auth/change_password',
        params=BaseData.l_d,
        headers=BaseData.headers,
    )
    assert response.status_code == HTTPStatus.OK
    response = make_post_request('/auth/change_login', data=BaseData.l_d3)
    assert response.status_code == HTTPStatus.OK
    response = make_get_request(
        '/auth/change_login',
        params=BaseData.l_d3,
        headers=BaseData.headers,
    )
    assert response.status_code == HTTPStatus.OK
