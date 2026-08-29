# Phish Triage Engine

Tenant-scoped Postgres persistence and a small FastAPI evidence-intake API. Intake only preserves and queues evidence: it does **not** fetch submitted URLs, automate a browser, render active content, contact phone/chat accounts, or accept credentials.

## Local setup

```bash
poetry install --with dev
docker compose up -d db
poetry run python -m pte migrate
PTE_ARTIFACT_ROOT=./artifacts poetry run uvicorn pte.api:app --host 127.0.0.1 --port 8000
```

Database settings use `PTE_DB_HOST`, `PTE_DB_PORT`, `PTE_DB_NAME`, `PTE_DB_USER`, and `PTE_DB_PASSWORD`. Immutable evidence bytes are content-addressed beneath `PTE_ARTIFACT_ROOT`; API responses expose hashes and metadata, never filesystem paths or submitted, normalized, parsed-header, or OCR content. URL responses include only a normalization-applied flag and SHA-256 summary, while the normalized indicator remains tenant-scoped internally. Tenants must be provisioned separately before intake.

Every request requires `tenant_uid`, `authorization_attested=true`, and `no_credentials_acknowledged=true`.

```bash
curl -X POST http://127.0.0.1:8000/v1/intake/url -H 'content-type: application/json' \
  -d '{"tenant_uid":"cust_EXAMPLE","authorization_attested":true,"no_credentials_acknowledged":true,"url":"https://example.test/path"}'

curl -X POST http://127.0.0.1:8000/v1/intake/email/paste -H 'content-type: application/json' \
  -d '{"tenant_uid":"cust_EXAMPLE","authorization_attested":true,"no_credentials_acknowledged":true,"mode":"headers_body","raw_headers":"From: sender@example.test","body":"Message text"}'

curl -X POST http://127.0.0.1:8000/v1/intake/ocr -H 'content-type: application/json' \
  -d '{"tenant_uid":"cust_EXAMPLE","authorization_attested":true,"no_credentials_acknowledged":true,"platform":"sms","ocr_text":"Alert line 1\nVisit https://example.test"}'
```

Uploads use multipart endpoints `/v1/intake/email/upload` and `/v1/intake/screenshot`. Email uploads accept matching `.eml`/`message/rfc822` or `.msg`/Outlook boundaries up to 10 MiB. Screenshots accept signature-matching PNG, JPEG, WebP, or PDF up to 15 MiB. Raw EML/MSG and canonical pasted-email bytes are preserved exactly. `.msg` files are preservation-only and are not parsed. Parsed-header artifacts for EML and full-header paste intake are linked to their raw parent and returned only as metadata and hashes. Forwarded email bodies are explicitly marked low fidelity.

Run verification with `poetry run pytest` and `poetry run python -m compileall -q pte tests`. Tests use the existing local Postgres fixture and create the disposable `phish_triage_test` database.

## Disposable scan-runner proof of concept

The scanner contract has an offline-only deterministic proof path. It performs
no DNS lookup or network I/O and accepts only the fixed benign fixture URL
`https://example.invalid/benign`. Use a new output root (the per-job directory
is intentionally single-use):

```bash
rm -rf ./tmp/scan-proof # optional cleanup of this project-local demo output
poetry run python -m pte scan-dry-run --output-root ./tmp/scan-proof
find ./tmp/scan-proof/dry-run-proof -maxdepth 1 -type f -print
```

The `scan-dry-run` CLI is intentionally filesystem-only. Application code can
use `run_dry_scan_job` for the DB-backed path: it advances an existing queued
job through the scan lifecycle and atomically persists completion through an
`ArtifactStore`. Execution or persistence errors propagate and leave the job
in a nonterminal state; they never record a false completion.

It writes a PNG screenshot, DOM snapshot, empty HAR, redirect-chain metadata,
and a manifest containing byte sizes, SHA-256 hashes, route provenance, and
explicit policy decisions. Forms and credential submission do not exist in the
contract. Workers use a fresh disposable profile. Downloads are blocked by
default; the only alternative is quarantine metadata/hash-only, with download
bytes never retained or submitted.

Live execution is fail-closed. `ScannerConfig(route_mode=PIA_SIDECAR)` is
required before a Docker command can be built. The command uses one `--rm`
container per job, a read-only root, a single writable per-job `/output` bind,
an explicit non-root UID/GID, an isolated no-exec `/tmp`, all capabilities
dropped, and `no-new-privileges`. It joins the VPN container namespace with Docker
`--network container:pia-vpn`. In Compose, the exact expected equivalent is:

```yaml
services:
  scanner-worker:
    network_mode: service:pia-vpn
```

`pia-vpn` is an external future sidecar/service name, not a bundled VPN setup.
No PIA usernames, passwords, keys, or credential placeholders are stored here.
URL policy resolves every DNS answer before a live invocation and rejects
loopback, private/LAN, link-local, multicast, reserved, unspecified, CGNAT,
and cloud-metadata addresses. Only HTTP(S) and default ports 80/443 are allowed
unless a non-default port is explicitly configured. The runtime network layer
must independently block private egress to mitigate DNS rebinding after the
pre-fetch validation.
