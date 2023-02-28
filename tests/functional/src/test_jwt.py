import datetime

import jwt
import pytest


def test_exception_jwt():
    exp = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(
        seconds=1
    )
    jwt_payload = jwt.encode(
        {'user_id': 1234, 'exp': exp},
        'secret',
    )
    # JWT payload is now expired
    # But with some leeway, it will still validate
    with pytest.raises(jwt.exceptions.ExpiredSignatureError):
        jwt.decode(jwt_payload, 'secret', algorithms=['HS256'])


def test_success_jwt():
    exp = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(
        seconds=1
    )
    data = {'user_id': 1234, 'exp': exp}
    jwt_payload = jwt.encode(
        data,
        'secret',
    )
    token = jwt.decode(jwt_payload, 'secret', algorithms=['HS256'])
    assert token['user_id'] == data['user_id']
