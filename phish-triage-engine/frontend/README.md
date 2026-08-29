# Phish Triage frontend

A self-contained, dependency-free static interface for the gated email evidence intake routes in `pte/api.py`.

## Run locally

Serve this directory with any static file server, for example:

```sh
python -m http.server 8080 --directory frontend
```

Open `http://127.0.0.1:8080`. The API defaults to `http://127.0.0.1:8000` and can be changed under **API connection**. The API must allow the frontend origin if they are served from different origins.

Without JavaScript, the forms remain readable and submit to the loopback API using standard HTML form behavior. JavaScript adds drag/drop, accessible tabs, client validation, JSON paste submission, configurable API routing, gated buttons, and privacy-safe status rendering.

## Intake behavior

- `.eml` and `.msg` email uploads, up to 10 MiB. `.msg` files are preserved only.
- Full headers plus body or forwarded-body paste fallback, up to 10 MiB.
- Both authorization and no-credentials attestations are required.
- Success displays only job ID, submission ID, source type, and fidelity.
- Screenshot/OCR is intentionally marked **Coming soon**. The backend routes are future-ready, including a 15 MiB screenshot limit, but this UI does not submit to them.

Do not place secrets or credentials in evidence. No build step or third-party dependency is required.
