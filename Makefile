#SHELL := /bin/bash -O globstar

test:
	make run
	pytest tests
	docker-compose down
test_api:
	make run
	sleep 2
	st run --base-url http://localhost:5000/ --checks all auth_service/schema/openapi_v1.yaml --show-errors-tracebacks --debug-output-file log_schema_test.json
	docker-compose down

lint:
	@echo
	poetry run ruff .
	@echo
	poetry run blue --check --diff --color .
	@echo
	poetry run mypy .
	@echo
	poetry run pip-audit --ignore PYSEC-2022-42969


format:
	poetry run ruff --silent --exit-zero --fix .
	poetry run blue .

build:
	poetry export -f requirements.txt --output auth_service/requirements.txt --without-hashes
	docker-compose build

run:
	cp .env.example .env
	cp .docker.env.example .docker.env
	poetry export -f requirements.txt --output auth_service/requirements.txt --without-hashes
	docker-compose -f docker-compose.yml up --build -d

run_dev:
	cp .env.example .env
	cp .docker.env.example .docker.env
	poetry export -f requirements.txt --output auth_service/requirements.txt --without-hashes
	docker-compose -f docker-compose.yml up --build
