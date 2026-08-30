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

## Automatic queued-job worker

`pte-worker` polls and atomically claims queued jobs for one explicit tenant.
Multiple workers may poll the same tenant: claims use row locks with `SKIP
LOCKED` and durably move a job to `normalizing`, so only one process can consume
it. The safe default pipeline is offline-only. Its scanner call is limited to
the fixed `https://example.invalid/benign` network-free proof; a submitted URL
is never passed to a scanner. Before scan artifacts or submitted-URL-derived
data are persisted, the worker requires returned policy evidence of
`network_io=false` and `route_mode=dry-run`, with the existing `direct-dev`
dry-proof route. Otherwise it fails closed. The accepted route and policy are
recorded in the tenant-scoped `scan_completed` event. The worker then persists
any derivable hostname indicator and performs deterministic local
enrichment/risk scoring with external providers marked unavailable, and calls
`persist_report_bundle` for canonical JSON and Markdown report artifacts.

Run one polling attempt (including a clean exit when the queue is empty):

```bash
PTE_ARTIFACT_ROOT=./artifacts poetry run pte-worker --tenant-uid 1234 --once
# Equivalent: make worker-once TENANT_UID=1234
```

Run continuously, or stop after a bounded number of consumed jobs:

```bash
poetry run pte-worker --tenant-uid 1234 --poll-interval 2
poetry run pte-worker --tenant-uid 1234 --max-jobs 10
```

Controls also have environment equivalents: `PTE_WORKER_TENANT_UID`,
`PTE_WORKER_POLL_INTERVAL`, `PTE_WORKER_MAX_JOBS`, `PTE_WORKER_ONCE`,
`PTE_WORKER_DRY_SCAN`, `PTE_WORKER_MODE`, and `PTE_WORKER_OUTPUT_ROOT`.
`PTE_WORKER_MODE=offline` is the default and never passes the submitted URL to
the scanner; its artifacts say `network_io=false` and are not live evidence.
Live jobs require the exact `vpn-live` mode (or `--mode vpn-live`),
`PTE_WORKER_DRY_SCAN=false`, and `PTE_SCANNER_ROUTE_MODE=pia-sidecar`. There is
no direct-live mode or fallback route. Console errors are deliberately generic.

Failures become terminal `blocked` or `failed` states with conservative reason
codes in tenant-scoped audit events. Polling never retries them automatically.
After correcting the local/input problem, an operator may explicitly requeue
one job; the normal atomic claim path then handles the retry:

```bash
poetry run pte-worker --tenant-uid 1234 --retry-job-id JOB_UUID
```

The per-job dry-scan output directory is deliberately single-use. Before an
explicit retry of a job that reached scan setup, move or remove that
project-local directory under `PTE_WORKER_OUTPUT_ROOT`; immutable artifacts in
`PTE_ARTIFACT_ROOT` are idempotent and content-addressed.

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

Live execution is fail-closed. Before target DNS, target probing, or navigation,
the worker proves `tun0` exists, the default route uses it, and an external
identity endpoint returns a public egress address from the VPN namespace.
Failure stops the job with no direct fallback. Scanner preflight owns URL/port
validation, rejection of private/LAN/loopback/link-local/metadata addresses,
and address pinning. The `pia-vpn` kill-switch/firewall independently owns
blocking private and non-tunnel egress for redirects and subresources; address
pinning is not a firewall.

Operators can prepare and inspect the non-secret future runtime contract for a
job UUID without starting a container:

```bash
PTE_SCANNER_WORKER_UID="$(id -u)" PTE_SCANNER_WORKER_GID="$(id -g)" \
  make scanner-prepare JOB_ID=00000000-0000-4000-8000-000000000001 \
  OUTPUT_ROOT=./tmp/scanner-jobs
```

For Compose, place the operator-provided files at these exact ignored paths.
The Compose sidecar always passes `/vpn/operator.auth` to OpenVPN explicitly;
the OVPN file does not need to embed a credential path:

```bash
mkdir -p ./secrets
chmod 700 ./secrets
install -m 600 /operator/source/region.ovpn ./secrets/operator.ovpn
install -m 600 /operator/source/pia.auth ./secrets/operator.auth
chmod 600 ./secrets/operator.ovpn ./secrets/operator.auth
export PTE_VPN_OVPN_PATH="$(pwd)/secrets/operator.ovpn"
export PTE_VPN_AUTH_FILE="$(pwd)/secrets/operator.auth"
export PTE_SCANNER_IMAGE=pte-scanner:operator-build
export PTE_WORKER_TENANT_UID=cust_EXAMPLE
```

For a host-controlled runtime contract, as an alternative to
`PTE_VPN_AUTH_FILE`, set both `PTE_VPN_USERNAME` and
`PTE_VPN_PASSWORD` in the process environment. Never set both authentication
modes. The Compose sidecar intentionally supports the mounted auth file only.
Never put real values in `.env.example`, source, logs, tickets, or shell command
arguments. The OVPN and auth files must not be accessible by
group or other users; configuration paths must be absolute, canonical regular
files and must not be symlinks. Project ignore rules cover `.env`, `secrets/`,
OVPN/auth files, and runtime output, but operators remain responsible for local
file permissions and secret handling.

Validate without starting or restarting infrastructure:

```bash
make vpn-live-config
make test-vpn-runtime
poetry run python -m compileall -q pte tests
```

The VPN service is opt-in under the `vpn-live` Compose profile. It is built from
`docker/vpn-sidecar`: an exact Alpine release and exact OpenVPN/network package
versions, with a project-owned entrypoint whose OUTPUT/FORWARD policies are
DROP before OpenVPN starts. Before the tunnel is up, only Docker DNS and the
resolved VPN server endpoints are allowed. After `tun0` is up, non-tunnel
egress and IPv6 are denied, and IPv4 private/RFC1918, loopback, link-local,
CGNAT, multicast, reserved/documentation, and metadata destinations are
rejected before the general `tun0` allow. Those namespace rules cover initial
navigation, redirects, and browser subresources.

The live queue worker is deliberately run on the Docker host, not in Compose:
it needs the Docker CLI to create and clean up one scanner container per job.
Do not mount `/var/run/docker.sock` into any worker or scanner container. The
per-job container has `--network container:pia-vpn` (the Docker CLI equivalent
of `network_mode: service:pia-vpn`), no published port, read-only root, a
bounded tmpfs, all capabilities dropped, `no-new-privileges`, and the declared
non-root UID/GID. Start the sidecar, then start the host worker with explicit
live settings:

```bash
docker compose --profile vpn-live up -d --build --wait pia-vpn
PTE_WORKER_MODE=vpn-live PTE_WORKER_DRY_SCAN=false \
PTE_SCANNER_ROUTE_MODE=pia-sidecar poetry run pte-worker \
  --tenant-uid "$PTE_WORKER_TENANT_UID"
```

This repository defines but does not pretend to provide the browser scanner
image. The operator build must produce the exact tag in `PTE_SCANNER_IMAGE`,
run as UID/GID `65532:65532`, and implement the bounded command
`scan --target URL --output /output`, writing only the approved artifact names
documented above. Because Docker's embedded resolver is not allowed through the
kill switch, that image must configure its browser to use DNS-over-HTTPS or an
explicit public resolver through the tunnel for redirect/subresource names; it
must apply the same public-address policy to those resolutions. Live mode fails
if that image/command is absent.
Real VPN verification is skipped when credentials/files are
absent. Unit tests use injected subprocess adapters and make no VPN call.
Starting the profile is a separate operator deployment action.

The prepare command creates one new mode-`0700` directory for that job and prints a
JSON contract. Reusing the job ID fails because output directories are
single-use. Container names are deterministic (`pte-scan-` plus the UUID hex),
so timeout cleanup always targets the exact per-job container. The contract
contains `network_mode: service:pia-vpn` and bounded stop/kill settings; it
never runs Docker. Its VPN section contains only the
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

The live design uses `ScannerConfig(route_mode=PIA_SIDECAR)` and the VPN
container namespace. Its per-job output directory must be mode `0700` and owned
by the configured worker UID/GID, defaulting to the container identity
`65532:65532`; invalid identity values fail validation. The eventual Docker
command also uses a unique explicit container name. Timeout cleanup acts on
that name with `docker stop`, escalates to `docker kill`, and always issues
`docker rm --force`, rather than merely terminating the Docker CLI process. Its
network setting is equivalent to this Compose relationship:

```yaml
network_mode: service:pia-vpn
```

`pia-vpn` is the opt-in, project-built Compose OpenVPN sidecar; the scanner is
created per job by the host worker and never receives the Docker socket.
No PIA usernames, passwords, keys, or credential placeholders are stored here.
URL policy resolves every DNS answer during validation and rejects
loopback, private/LAN, link-local, multicast, reserved, unspecified, CGNAT,
and cloud-metadata addresses. Only HTTP(S) and default ports 80/443 are allowed
unless a non-default port is explicitly configured. Approved DNS answers are
pinned in the disposable live container command.
