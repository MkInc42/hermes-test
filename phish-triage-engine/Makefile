.PHONY: dev-up migrate test run-api enrich-fixture

dev-up:
	docker compose up -d --wait db
	poetry run python -m pte migrate

migrate:
	poetry run python -m pte migrate

test:
	poetry run pytest

run-api:
	poetry run uvicorn pte.api:app --host 127.0.0.1 --port 8000

# Usage: make enrich-fixture TENANT_UID=cust_EXAMPLE JOB_ID=<uuid>
enrich-fixture:
	poetry run pte-enrich --tenant-uid "$(TENANT_UID)" --job-id "$(JOB_ID)" --fixture
