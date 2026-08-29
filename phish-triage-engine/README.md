# Phish Triage Engine

Tenant-scoped Postgres persistence and a small FastAPI evidence-intake API. Intake only preserves and queues evidence: it does **not** fetch submitted URLs, automate a browser, render active content, contact phone/chat accounts, or accept credentials.

## Local setup

```bash
poetry install --extras dev
make dev-up
make run-api
```

The equivalent exact Poetry commands are:

```bash
docker compose up -d --wait db
poetry run python -m pte migrate
PTE_ARTIFACT_ROOT=./artifacts poetry run uvicorn pte.api:app --host 127.0.0.1 --port 8000
poetry run pytest
```

`make run-api` and the explicit Uvicorn command bind only to loopback. Do not
change the host to `0.0.0.0` for this internal development service.

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

## Analyst report artifacts

`pte.reports` assembles schema-versioned analyst content packs from the canonical,
tenant-scoped job bundle. JSON and Markdown renderings are deterministic and
contain only artifact IDs, SHA-256 references, defanged IOCs, source status,
explicit fact/inference labels, caveats, TTPs, safety controls, and defensive
recommendations. Raw bodies, raw URLs, URL queries/tokens, PII, artifact bytes,
storage pointers, and local paths are excluded.

Application code persists both renderings atomically with
`persist_report_bundle(..., storage_writer=artifact_store.put)`. This creates two
`derived_artifacts` rows of kind `report_file`, versions the final `reports` row,
records its evidence manifest and hashes, and advances the job through reporting
to completed with audit events.

Scoped exports require the owning tenant UID and never read artifact bytes:

```bash
curl 'http://127.0.0.1:8000/v1/reports/JOB_UUID/content-pack?tenant_uid=cust_EXAMPLE'
curl 'http://127.0.0.1:8000/v1/reports/JOB_UUID/markdown?tenant_uid=cust_EXAMPLE'
```

A missing or wrong tenant resolves as not found. These are protected internal
report reads, not public scanning or browser endpoints.

## Disposable scan-runner proof of concept

The scanner contract has an offline-only deterministic proof path. It performs
no DNS lookup or network I/O and accepts only the fixed benign fixture URL
`https://example.invalid/benign`. Use a new output root (the per-job directory
is intentionally single-use):

```bash
rm -rf ./tmp/scan-proof # optional cleanup of this project-local demo output
poetry run python -m pte scan-dry-run --output-root ./tmp/scan-proof
# Equivalent: make scan-proof OUTPUT_ROOT=./tmp/scan-proof
find ./tmp/scan-proof/dry-run-proof -maxdepth 1 -type f -print
```

The `scan-dry-run` CLI is intentionally filesystem-only. Application code can
use `run_dry_scan_job` for the DB-backed path: it advances an existing queued
job through the scan lifecycle and atomically persists completion through an
`ArtifactStore`. Execution or persistence errors propagate and never record a
false completion. When the database remains available, policy failures
atomically record a `blocked` job/source status and scan event, while
execution/storage failures record `failed` status and events.

It writes a PNG screenshot, DOM snapshot, empty HAR, redirect-chain metadata,
and a manifest containing byte sizes, SHA-256 hashes, route provenance, and
explicit policy decisions. Forms and credential submission do not exist in the
contract. Workers use a fresh disposable profile. Downloads are blocked by
default; the only alternative is quarantine metadata/hash-only, with download
bytes never retained or submitted.

Live execution is fail-closed and command construction is currently disabled.
Preflight DNS validation alone cannot prevent rebinding when the browser later
resolves an attacker-controlled hostname inside an unrestricted shared network
namespace. Live commands will remain disabled until the runtime contract pins
validated public addresses and independently blocks private egress.

Operators can prepare and inspect the non-secret future runtime contract for a
job UUID without starting a container:

```bash
PTE_SCANNER_WORKER_UID="$(id -u)" PTE_SCANNER_WORKER_GID="$(id -g)" \
  make scanner-prepare JOB_ID=00000000-0000-4000-8000-000000000001 \
  OUTPUT_ROOT=./tmp/scanner-jobs
```

Before preparing the contract, Reknown should store the provider-issued OVPN
file and either an OpenVPN auth file or inline credentials locally, outside
version control. Use restrictive permissions and absolute canonical paths:

```bash
mkdir -p ./secrets
chmod 700 ./secrets
chmod 600 ./secrets/operator.ovpn ./secrets/operator.auth
export PTE_VPN_OVPN_PATH="$(pwd)/secrets/operator.ovpn"
export PTE_VPN_AUTH_FILE="$(pwd)/secrets/operator.auth"
```

As an alternative to `PTE_VPN_AUTH_FILE`, set both `PTE_VPN_USERNAME` and
`PTE_VPN_PASSWORD` in the process environment. Never set both authentication
modes, and never put real values in `.env.example`, source, logs, tickets, or
shell command arguments. The OVPN and auth files must not be accessible by
group or other users; configuration paths must be absolute, canonical regular
files and must not be symlinks. Project ignore rules cover `.env`, `secrets/`,
OVPN/auth files, and runtime output, but operators remain responsible for local
file permissions and secret handling.

The command creates one new mode-`0700` directory for that job and prints a
JSON contract. Reusing the job ID fails because output directories are
single-use. Container names are deterministic (`pte-scan-` plus the UUID hex),
so timeout cleanup always targets the exact per-job container. The contract
contains `network_mode: service:pia-vpn`, bounded stop/kill settings, and the
two missing live gates; it never runs Docker. Its VPN section contains only the
authentication mode and OVPN path, never the auth-file path, username, or
password. No credentials are placed in command-line arguments.

## One-shot OSINT enrichment worker

The worker always loads an existing `queued` job under an explicit tenant and
persists its canonical enrichment artifact, normalized source observations,
risk score, and source status to Postgres. It is not a JSON-only exporter.
Safe/local mode uses the job's persisted URL indicator and performs no network
I/O:

```bash
PTE_ARTIFACT_ROOT=./artifacts poetry run pte-enrich \
  --tenant-uid cust_EXAMPLE --job-id JOB_UUID
```

The bundled FedEx fixture fills every provider slot without network access and
is useful for an operator smoke test against a queued job:

```bash
PTE_ARTIFACT_ROOT=./artifacts poetry run pte-enrich \
  --tenant-uid cust_EXAMPLE --job-id JOB_UUID --fixture
# Equivalent: make enrich-fixture TENANT_UID=cust_EXAMPLE JOB_ID=JOB_UUID
```

DNS A/AAAA resolution is the sole live adapter and must be explicitly enabled.
It is passive, has a bounded deadline, never connects to the resolved service,
and normalizes timeout/unavailable conditions instead of raising them:

```bash
poetry run pte-enrich --tenant-uid cust_EXAMPLE --job-id JOB_UUID \
  --enable-dns --dns-timeout 2
```

URLhaus, OTX, Google Safe Browsing, RDAP/WHOIS, ASN/hosting, and TLS/certificate
transparency remain `unavailable` in safe/local mode. The worker does not call
external reputation APIs or infer a benign verdict when credentials are absent.
No active scanning, browser automation, credential submission, cron job, or
public deployment is part of this entrypoint.

Verify the persisted records directly with the same local database settings:

```bash
docker compose exec db psql -U pte -d phish_triage -c \
  "SELECT source,status,observable_value FROM enrichment_observations WHERE tenant_uid='cust_EXAMPLE' AND job_id='JOB_UUID' ORDER BY source;"
docker compose exec db psql -U pte -d phish_triage -c \
  "SELECT classification,confidence,score FROM risk_scores WHERE tenant_uid='cust_EXAMPLE' AND job_id='JOB_UUID';"
docker compose exec db psql -U pte -d phish_triage -c \
  "SELECT source_type,status,status_detail FROM source_status WHERE tenant_uid='cust_EXAMPLE' AND job_id='JOB_UUID';"
```

### Enrichment contract

`pte.enrichment` defines the deterministic backend contract for passive OSINT
enrichment and evidence-based risk scoring. Current
source outputs are fixed by schema version 1: DNS, RDAP/WHOIS, ASN/hosting,
TLS/certificate transparency, Google Safe Browsing, URLhaus/abuse.ch, OTX, URL
parsing tricks, domain age, static DOM indicators, and source status. Each
source carries `status`, `provider`, `observable`, normalized `data`, and
explicit `limitations` so clean or missing reputation lookups do not become a
black-box benign verdict.

The score is a deterministic weighted-evidence model (`deterministic-weighted-
evidence-v1`) that stores the exact evidence and limitations in `risk_scores`
and persists the canonical JSON as an `enrichment_payload` artifact. URL parsing
uses a pinned complete offline Public Suffix List snapshot for
registrable-domain decisions instead of live PSL fetches or last-two-label
guesses. DOM parsing is static only: credential, card, OTP, form, script,
iframe, and support/verify CTA
indicators are extracted without JavaScript execution or credential submission.
`tests/fixtures/fedex_smishing_case.json` is the FedEx-style smishing fixture
used by `tests/test_enrichment.py` to prove the JSON contract, source-status
coverage, risk evidence, limitations, and tenant-scoped Postgres persistence.

The future design retains `ScannerConfig(route_mode=PIA_SIDECAR)` and the VPN
container namespace. Its per-job output directory must be mode `0700` and owned
by the configured worker UID/GID, defaulting to the container identity
`65532:65532`; invalid identity values fail validation. The eventual Docker
command must also use a unique explicit container name. Timeout cleanup acts on
that name with `docker stop`, escalates to `docker kill`, and always issues
`docker rm --force`, rather than merely terminating the Docker CLI process. In
Compose, the intended PIA namespace equivalent remains:

```yaml
services:
  scanner-worker:
    network_mode: service:pia-vpn
```

`pia-vpn` is an external future sidecar/service name, not a bundled VPN setup.
No PIA usernames, passwords, keys, or credential placeholders are stored here.
URL policy resolves every DNS answer during validation and rejects
loopback, private/LAN, link-local, multicast, reserved, unspecified, CGNAT,
and cloud-metadata addresses. Only HTTP(S) and default ports 80/443 are allowed
unless a non-default port is explicitly configured. No validated hostname is
currently passed to a live container.
