from abc import abstractmethod
from datetime import datetime

import redis

from src.core.config import APP_CONFIG, REDIS_CONFIG


class TokenBlocklist:
    @abstractmethod
    def revoke_token(self, token_identifier: str, ex: int) -> bool:
        """Помечает токен как отозванный.

        Args:
            token_identifier (str): идентификатор токена
            ex (int): время жизни токена в секундах

        Returns:
            bool: True, если операция прошла успешно, иначе False
        """
        ...

    @abstractmethod
    def revoke_all_user_tokens(self, user_identity: str) -> bool:
        """Помечает все токены пользователя, созданные до текущего момента,
        как отозванные.

        Args:
            user_identity (str): идентификатор пользователя

        Returns:
            bool: True, если операция прошла успешно, иначе False
        """
        ...

    @abstractmethod
    def is_token_revoked(
        self,
        token_identifier: str,
        user_identifier: str,
        token_init_time: int,
    ) -> bool:
        """Проверяет, отозван ли токен.

        Args:
            token_identifier (str): идентификатор токена
            user_identifier (str): идентификатор пользователя
            token_init_time (int): время создания токена

        Returns:
            bool: True, если токен отозван, иначе False
        """
        ...


class RedisTokenBlocklist(TokenBlocklist):
    def __init__(self, redis_config: dict[str, str | int]):
        self.redis = redis.Redis(**redis_config)   # type: ignore

    def revoke_token(self, token_identifier: str, ex: int) -> bool:
        return bool(self.redis.set(token_identifier, 1, ex=ex))

    def revoke_all_user_tokens(self, user_identity: str) -> bool:
        return bool(
            self.redis.set(
                user_identity,
                datetime.now().timestamp(),
                ex=APP_CONFIG['JWT_REFRESH_TOKEN_EXPIRES'],
            )
        )

    def is_token_revoked(
        self,
        token_identifier: str,
        user_identifier: str,
        token_init_time: int,
    ) -> bool:
        if self.redis.get(token_identifier):
            return True
        if revoke_datetime := self.redis.get(user_identifier):
            revoke_datetime = float(revoke_datetime)
            return bool(token_init_time < revoke_datetime)

        return False


jwt_redis_blocklist = RedisTokenBlocklist(dict(REDIS_CONFIG))
