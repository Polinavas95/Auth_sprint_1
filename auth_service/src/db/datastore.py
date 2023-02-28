import uuid
from abc import abstractmethod
from typing import Any, Generic, TypeVar

from loguru import logger
from peewee import Model

from src.core.models import LoginEvent as PeeweeLoginEvent
from src.core.models import Role as PeeweeRole
from src.core.models import User as PeeweeUser
from src.core.models import UserRoles as PeeweeUserRoles
from src.db.postgres import db

Role = TypeVar('Role')
User = TypeVar('User')
LoginEvent = TypeVar('LoginEvent')

AbstractModel = TypeVar('AbstractModel')


class Datastore(Generic[AbstractModel]):
    def __init__(self, db: Any):
        self.db = db

    def commit(self) -> None:
        pass

    def put(self, model: AbstractModel) -> AbstractModel:
        raise NotImplementedError

    def delete(self, model: AbstractModel) -> None:
        raise NotImplementedError


class PeeweeDatastore(Datastore[Model]):
    def __init__(self, db: Any):
        super().__init__(db)

    def put(self, model: Model) -> Model:
        with self.db.atomic():
            model.save()
        return model

    def delete(self, model: Model) -> None:
        model.delete_instance(recursive=True)


class UserDatastore(Generic[User, Role, LoginEvent]):
    def __init__(
        self,
        user_model: User,
        role_model: Role,
        history_model: LoginEvent,
    ):
        self.user_model = user_model
        self.role_model = role_model
        self.history_model = history_model

    @abstractmethod
    def find_user(self, **kwargs: Any) -> User | None:
        raise NotImplementedError

    @abstractmethod
    def find_role(self, **kwargs: Any) -> Role | None:
        raise NotImplementedError

    @abstractmethod
    def find_or_create_role(self, **kwargs: Any) -> Role | None:
        raise NotImplementedError

    @abstractmethod
    def add_role_to_user(self, user: User, role: Role | str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def remove_role_from_user(self, user: User, role: Role | str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def delete_role(self, role: Role | str) -> None:
        raise NotImplementedError

    @abstractmethod
    def create_user(self, **kwargs: Any) -> User:
        raise NotImplementedError

    @abstractmethod
    def delete_user(self, user: User) -> bool:
        raise NotImplementedError

    @abstractmethod
    def delete_history(self, user: LoginEvent) -> bool:
        raise NotImplementedError


class PeeweeUserDatastore(
    PeeweeDatastore, UserDatastore[PeeweeUser, PeeweeRole, PeeweeLoginEvent]
):
    def __init__(self, db: Any):
        """
        :param db: A peewee database instance
        :param role_link: A model implementing the many-to-many user-role
            relation
        """
        PeeweeDatastore.__init__(self, db)
        UserDatastore.__init__(self, PeeweeUser, PeeweeRole, PeeweeLoginEvent)
        self.UserRole = PeeweeUserRoles

    def find_user(
        self, case_insensitive: bool = False, **kwargs: Any
    ) -> User | None:
        from peewee import fn as peeweeFn   # noqa

        try:
            if case_insensitive:
                # While it is of course possible to pass in multiple
                # keys to filter on that isn't the normal use case.
                # If caller asks for case_insensitive
                # AND gives multiple keys - throw an error.
                if len(kwargs) > 1:
                    raise ValueError(
                        'Case insensitive option only supports single key'
                    )
                attr, identifier = kwargs.popitem()
                return self.user_model.get(
                    peeweeFn.lower(getattr(self.user_model, attr))
                    == peeweeFn.lower(identifier)
                )
            return self.user_model.filter(**kwargs).get()
        except self.user_model.DoesNotExist:
            return None

    def find_role(self, role):
        try:
            return self.role_model.get(name=role)
        except self.role_model.DoesNotExist:
            return None

    def create_user(self, **kwargs: Any) -> User:
        """Creates and returns a new user from the given parameters."""
        roles = kwargs.pop('roles', [])
        user = self.user_model(**kwargs)
        user = self.put(user)
        logger.info(user)
        for role in roles:
            self.add_role_to_user(user, self.role_model.get(name=role))
        self.put(user)
        return user

    def delete_user(self, user: 'User') -> None:
        """Deletes the specified user.
        :param user: The user to delete
        """
        self.delete(user)

    def create_role(self, **kwargs: Any) -> 'Role':
        """
        Creates and returns a new role from the given parameters.
        Supported params (depending on RoleModel):
        :kwparam name: Role name
        :kwparam permissions: a list, set, tuple or comma separated string.
            These are user-defined strings that correspond to args used with
            @permissions_required()
            .. versionadded:: 3.3.0
        """

        # Usually we just use raw DB model create - for permissions we want to
        # be nicer and allow sending in a list or set or a single string.
        if 'permissions' in kwargs and hasattr(self.role_model, 'permissions'):
            perms = kwargs['permissions']
            if isinstance(perms, (set, tuple)):
                perms = list(perms)
            elif isinstance(perms, str):
                perms = [p.strip() for p in perms.split(',')]
            kwargs['permissions'] = perms

        role = self.role_model(**kwargs)
        return self.put(role)

    def delete_role(self, role) -> None:
        """Deletes the specified role.
        :param role: The role to delete
        """
        self.delete(role)

    def delete_history(self, history) -> None:
        """Deletes the specified role.
        :param history: The history to delete
        """
        self.delete(history)

    def find_or_create_role(self, name: str, **kwargs: Any) -> 'Role':
        """Returns a role matching the given name or creates it with any
        additionally provided parameters.
        """
        return self.find_role(name) or self.create_role(name=name, **kwargs)

    def add_role_to_user(self, user: User, role: Role):
        """Adds a role to a user.
        :param user: The user to manipulate
        :param role: The role to add to the user
        """
        result = self.UserRole.select().where(
            self.UserRole.user == user, self.UserRole.role == role
        )
        logger.info(result)
        if result.count():
            return False
        self.put(self.UserRole.create(user=user, role=role))
        return True

    def remove_role_from_user(self, user, role):
        """Removes a role from a user.
        :param user: The user to manipulate
        :param role: The role to remove from the user
        """
        result = self.UserRole.select().where(
            self.UserRole.user == user, self.UserRole.role == role
        )
        if result.count():
            query = self.UserRole.delete().where(
                self.UserRole.user == user, self.UserRole.role == role
            )
            query.execute()
            return True
        return False

    def set_uniquifier(
        self, user: 'User', uniquifier: str | None = None
    ) -> None:
        """Set user's identity key.
        This will immediately render outstanding auth tokens,
        session cookies and remember cookies invalid.
        :param user: User to modify
        :param uniquifier: Unique value - if none then uuid.uuid4().hex is used
        .. versionadded:: 3.3.0
        """
        if not uniquifier:
            uniquifier = uuid.uuid4().hex
        user.fs_uniquifier = uniquifier
        self.put(user)


datastore = PeeweeUserDatastore(db)
