import pytest
import redis
from functional.settings import TestSettings
from requests import Response, get, post

settings = TestSettings()


@pytest.fixture
def make_get_request():
    def inner(
        method: str, params: dict = None, headers: dict = None
    ) -> Response:
        params = params or {}
        headers = headers or {}
        url = settings.base_api + method
        response = get(url, params=params, headers=headers)
        return response

    return inner


@pytest.fixture
def make_post_request():
    def inner(
        method: str, data: dict = None, headers: dict = None
    ) -> Response:
        data = data or {}
        headers = headers or {}
        url = settings.base_api + method
        response = post(url, data=data, headers=headers)
        return response

    return inner


@pytest.fixture
def make_post_request_form():
    def inner(
        method: str, data: dict = None, headers: dict = None, json=None
    ) -> Response:
        data = data or {}
        headers = headers or {}
        json = json or {}
        url = settings.base_api + method
        response = post(url, json=json, headers=headers)
        return response

    return inner


@pytest.fixture(scope='session')
def redis_client():
    return redis.Redis(
        settings.redis_host, settings.redis_port
    )  # type: ignore
