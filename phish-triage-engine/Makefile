.PHONY: dev-up migrate test run-api enrich-fixture scan-proof scanner-prepare worker-once worker

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

scan-proof:
	poetry run python -m pte scan-dry-run --output-root "$(OUTPUT_ROOT)"

# Usage: make scanner-prepare JOB_ID=<uuid> OUTPUT_ROOT=./tmp/scanner-jobs
scanner-prepare:
	poetry run python -m pte scanner-prepare --job-id "$(JOB_ID)" --output-root "$(OUTPUT_ROOT)"

# Tenant-scoped safe/offline queue worker. Usage: make worker-once TENANT_UID=1234
worker-once:
	poetry run pte-worker --tenant-uid "$(TENANT_UID)" --once

worker:
	poetry run pte-worker --tenant-uid "$(TENANT_UID)"
