# Phish Triage frontend: local operator guide

This is a dependency-free static UI for the Phish Triage Intake API. The loopback setup is preferred. The documented LAN setup is for the trusted private network at `192.168.1.115` only; LAN binding is trusted-network-only and must not be exposed to an untrusted network or the public internet.

## Prepare Postgres

The API requires Postgres, an applied schema, and a pre-provisioned tenant. From the repository root, start the repository's loopback-only development database and apply migrations:

```sh
docker compose up -d --wait db
poetry run python -m pte migrate
```

The default connection is `127.0.0.1:55432`, database `phish_triage`, user `pte`, with the local-development password defined in `docker-compose.yml`. Override it with `PTE_DB_HOST`, `PTE_DB_PORT`, `PTE_DB_NAME`, `PTE_DB_USER`, and `PTE_DB_PASSWORD`. Set `PTE_ARTIFACT_ROOT` if evidence artifacts should be stored somewhere other than the default `./artifacts` directory. Database migrations do not create an intake tenant; the `tenant_uid` used in the UI or examples must already be provisioned.

## Start the API and frontend

Run these commands from the repository root in separate terminals.

API:

```sh
poetry run uvicorn pte.api:app --host 127.0.0.1 --port 8000
```

Frontend:

```sh
python3 -m http.server 8080 --bind 127.0.0.1 --directory frontend
# Or, when using the Poetry environment:
poetry run python -m http.server 8080 --bind 127.0.0.1 --directory frontend
```

This split-origin setup uses frontend port `8080` and API port `8000`. The API permits the static frontend origins `http://127.0.0.1:8080`, `http://localhost:8080`, and `http://[::1]:8080`; keep whichever host spelling you choose on port `8080`. Open the UI at <http://127.0.0.1:8080>. Confirm API/database readiness at <http://127.0.0.1:8000/health>; a ready service returns `{"status":"ok"}`. In the UI's **API connection** section, set **API base URL** to `http://127.0.0.1:8000` and select **Use address**. The value is stored in browser local storage.

For access from the documented trusted LAN, bind the services to the host's LAN address instead:

```sh
poetry run uvicorn pte.api:app --host 192.168.1.115 --port 8012
python3 -m http.server 8088 --bind 192.168.1.115 --directory frontend
```

Open the trusted-LAN frontend at <http://192.168.1.115:8088> and check the API at <http://192.168.1.115:8012/health>. A non-loopback HTTP(S) page automatically selects the same page hostname on API port `8012`; loopback pages continue to select port `8000`. A manually entered or browser-saved API origin is accepted only when it is HTTP(S) and uses loopback or exactly the current page hostname. Credentials, paths, query strings, and fragments are rejected. The API CORS allowlist contains the single documented LAN frontend origin `http://192.168.1.115:8088`; other LAN hosts or ports are not trusted.

To smoke-check the browser preflight directly, run:

```sh
curl --include --request OPTIONS http://127.0.0.1:8000/v1/intake/url \
  --header 'Origin: http://127.0.0.1:8080' \
  --header 'Access-Control-Request-Method: POST' \
  --header 'Access-Control-Request-Headers: content-type'
```

A working response is `200 OK` and includes `access-control-allow-origin: http://127.0.0.1:8080`, `access-control-allow-methods: POST`, and an allowed `content-type` request header.

Every intake requires an existing tenant UID plus both authorization and no-credentials attestations. Submit only evidence you are authorized to provide. Remove passwords, tokens, session values, recovery codes, private keys, and all other credentials before submission.

## Safe JSON examples

The reserved `.test` names below are inert examples. Replace `cust_EXAMPLE` only with a tenant UID that exists in the local database.

URL intake (`POST /v1/intake/url`):

```json
{
  "tenant_uid": "cust_EXAMPLE",
  "authorization_attested": true,
  "no_credentials_acknowledged": true,
  "url": "https://example.test/suspicious-path"
}
```

OCR intake (`POST /v1/intake/ocr`):

```json
{
  "tenant_uid": "cust_EXAMPLE",
  "authorization_attested": true,
  "no_credentials_acknowledged": true,
  "ocr_text": "Example notification. Review at https://example.test/review",
  "platform": "sms",
  "engine": "manual-example",
  "confidence": 0.95
}
```

Screenshot intake is multipart, not JSON. Its request shape is:

```sh
curl --request POST http://127.0.0.1:8000/v1/intake/screenshot \
  --form 'tenant_uid=cust_EXAMPLE' \
  --form 'authorization_attested=true' \
  --form 'no_credentials_acknowledged=true' \
  --form 'file=@/absolute/path/to/safe-example.png;type=image/png' \
  --form 'ocr_text=Optional reviewed OCR text with no credentials'
```

Omit the `ocr_text` form field when no reviewed OCR text is available. The file extension, declared media type, and file signature must agree.

## Intake formats and limits

- URLs must be absolute HTTP or HTTPS URLs, may not contain username/password user information, and are limited to 4,096 characters. Intake stores the URL but does not fetch it.
- OCR text is limited to 100,000 characters. `platform` and `engine` are optional strings of at most 100 characters; `confidence` is optional and must be from 0 through 1.
- Prefer an original `.eml` email because its headers can be parsed. A matching `.eml`/`message/rfc822` upload is limited to 10 MiB.
- `.msg` is preservation-only: the original bytes are retained, but the message is not parsed. A matching `.msg`/`application/vnd.ms-outlook` upload is limited to 10 MiB.
- Pasted headers and body have a combined UTF-8 limit of 10 MiB. Full headers plus body provide better fidelity; a forwarded body is explicitly recorded as low fidelity.
- Screenshots accept signature-matching PNG, JPEG, WebP, or PDF files up to 15 MiB. Optional OCR text uses the same 100,000-character limit.
- Tenant UIDs are limited to 255 characters. Both attestations must be `true` for every request.

## Privacy behavior

The UI deliberately renders only privacy-safe submission metadata: job ID, submission ID, source type, fidelity, and state. It does not render submitted evidence, normalized URLs, OCR content, parsed headers, artifact paths, or arbitrary API response/error bodies. Evidence remains sensitive even though the UI suppresses it; protect the Postgres database and `PTE_ARTIFACT_ROOT`, and do not use real credentials in examples or submissions.
