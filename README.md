# Сервис авторизации
API для авторизации и аутентификации, основанная на JWT-токенах и RBAC подходе к управлению доступом.
https://github.com/Barahlush/Auth_sprint_1

## Настройка проекта
Проект использует Poetry для управления виртуальным окружениям и зависимостями.
#### Установите Poetry (не входя в виртуальное окружение)
```shell
pip3 install poetry
```

<details>
<summary><h3 style="display: inline;"> 
Как настроить проект для разработки
</h3></summary>

#### 1. Установите зависимости проекта
```shell
poetry install
```

#### 2. Используйте команды poetry для работы
https://python-poetry.org/docs/cli/

https://python-poetry.org/docs/managing-dependencies/

**Активировать виртуальное окружение:**
```shell
poetry shell
```

**Запустить команду в виртуальном окружении** (можно запускать извне окружения)
```shell
poetry run python3 auth_service/src/main.py # пример запуска команды
```

**Установить библиотеку в виртуальном окружении** (можно запускать извне окружения)
```shell
poetry add pendulum==2.0.5 # пример установки библиотеки
```
**Установить библиотеку, которая используется только в разработке** (можно запускать извне окружения)
```shell
poetry add pendulum==2.0.5 --group dev
```

#### 3. Установите pre-commit хуки
```shell
poetry run pre-commit install
```

#### 4. Механизм миграции Базы данных
Чтобы увидеть возможности использования peewee-migrate используйте команду
```shell
pw_migrate --help
```
Для создания миграции
```shell
pw_migrate create [OPTIONS] NAME
```
Для запуска процесса миграции
```shell
pw_migrate migrate [OPTIONS]
```
Чтобы откатить созданную миграцию
```shell
pw_migrate rollback [OPTIONS]
```

Источник: https://github.com/klen/peewee_migrate
</details>


<details>
<summary><h3 style="display: inline;"> 
Make команды
</h3></summary>

- `make tests` - запускает тесты из `./tests`
- `make lint` - проводит линтинг с помощью ruff (flake8 + isort + ...), mypy и blue (форк blake)
- `make format` - форматирует код с помощью blue
- `make build` - собирает сервис через docker-compose
- `make run` - запускает сервис через docker-compose

</details>

<details>
<summary><h3 style="display: inline;"> 
Как настроить проект для запуска
</h3></summary>
</details>

#### 1. Установите зависимости проекта
```shell
poetry install --without dev
```

#### 2. Запустите сервис
```shell
make run
```

- Код написан по правилам pep8: при запуске [линтера](https://semakin.dev/2020/05/python_linters/){target="_blank"} в консоли не появляется предупреждений и возмущений;
- Все ключевые методы покрыты тестами: каждый ответ каждой ручки API и важная бизнес-логика тщательно проверены;
- У тестов есть понятное описание, что именно проверяется внутри. Используйте [pep257](https://www.python.org/dev/peps/pep-0257/){target="_blank"}; 
- Заполните README.md так, чтобы по нему можно было легко познакомиться с вашим проектом. Добавьте короткое, но ёмкое описание проекта. По пунктам опишите как запустить приложения с нуля, перечислив полезные команды. Упомяните людей, которые занимаются проектом и их роли. Ведите changelog: описывайте, что именно из задания модуля уже реализовано в вашем сервисе и пополняйте список по мере развития.
- Вы воспользовались лучшими практиками описания конфигурации приложений из урока. 

## Авторы
[Polinavas95](https://github.com/Polinavas95)
| <tatsuchan@mail.ru>

[Barahlush](https://github.com/Barahlush) | <baraltiva@gmail.com>
