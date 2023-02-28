from flask_admin.contrib.peewee import ModelView  # type: ignore
from flask_admin.form import SecureForm  # type: ignore
from flask_jwt_extended import get_current_user, jwt_required
from loguru import logger
from peewee import CharField, ForeignKeyField, Model

from src.core.models import Role, User, UserRoles
from src.db.postgres import db


class UserInfo(Model):
    key = CharField(max_length=64)
    value = CharField(max_length=64)

    user = ForeignKeyField(User)

    def __str__(self) -> str:
        return f'{self.key} - {self.value}'

    class Meta:
        database = db


class RoleInfo(Model):
    key = CharField(max_length=64)
    value = CharField(max_length=64)

    role = ForeignKeyField(Role)

    def __str__(self) -> str:
        return f'{self.key} - {self.value}'

    class Meta:
        database = db


class UserRolesInfo(Model):
    key = CharField(max_length=64)
    value = CharField(max_length=64)

    user_role = ForeignKeyField(UserRoles)

    def __str__(self) -> str:
        return f'{self.key} - {self.value}'

    class Meta:
        database = db


class UserAdmin(ModelView):  # type: ignore
    form_base_class = SecureForm
    inline_models = (UserInfo,)
    column_exclude_list = ('password_hash',)

    @jwt_required()   # type: ignore
    def is_accessible(self) -> bool:
        logger.info('Checking access to admin panel')
        current_user = get_current_user()
        if not current_user:
            return False
        for role in current_user.roles:
            if role.name == 'admin':
                return True
        return False


class RoleAdmin(ModelView):  # type: ignore
    form_base_class = SecureForm
    inline_models = (RoleInfo,)

    @jwt_required()   # type: ignore
    def is_accessible(self) -> bool:
        logger.info('Checking access to admin panel')
        current_user = get_current_user()
        if not current_user:
            return False
        for role in current_user.roles:
            if role.name == 'admin':
                return True
        return False


class UserRolesAdmin(ModelView):  # type: ignore
    form_base_class = SecureForm
    inline_models = (UserRolesInfo,)

    @jwt_required()   # type: ignore
    def is_accessible(self) -> bool:
        logger.info('Checking access to admin panel')
        current_user = get_current_user()
        if not current_user:
            return False
        for role in current_user.roles:
            if role.name == 'admin':
                return True
        return False
