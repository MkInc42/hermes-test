# Covered On SEO Audit Pipeline

The pipeline crawls a site with Playwright by default, runs performance and security checks, and writes HTML reports plus CSV data under an audit output directory.

## Docker deployment

The image includes Python 3.12, Playwright Chromium, and Screaming Frog SEO Spider. Screaming Frog is proprietary software, so its Debian installer is supplied by the operator at build time and is not committed to this repository.

### 1. Prepare the installer

Obtain the approved Screaming Frog SEO Spider Linux `.deb` (the local installation is version 24.3) and copy it into this directory, or point Compose at an equivalent path inside the build context:

```bash
cp /path/to/screamingfrogseospider_24.3_amd64.deb ./screamingfrogseospider.deb
# Or use a different filename:
export SCREAMING_FROG_DEB=screamingfrogseospider_24.3_amd64.deb
```

The `.deb` is intentionally not tracked. Keep it in a protected local build workspace and remove it after building if the host does not need it.

### 2. Build and start the safe default service

```bash
docker compose build
docker compose up -d
docker compose ps
```

`up` does not start an external crawl. The service serves persisted reports from `/data/audits` on its internal port 8000 and remains available to an internal reverse proxy. No host port is published by default.

Check the image and service health:

```bash
docker compose exec seo-audit python /app/healthcheck.py
docker compose ps
```

### 3. Run an audit

Override the safe report-server command for a one-shot audit. The output remains in the named `covered-on-seo-audit-data` volume:

```bash
docker compose run --rm seo-audit \
  python pipeline.py https://example.com \
  --max-urls 100 --max-depth 3
```

Use the Screaming Frog backend after the separate integration is available:

```bash
docker compose run --rm seo-audit \
  python pipeline.py https://example.com \
  --crawler frog --max-urls 100 --max-depth 3
```

The default Playwright crawler uses the Chromium browser baked into the image. Do not pass `--no-crawl` when an audit needs crawl data.

### Volumes and permissions

- `covered-on-seo-audit-data` stores audit output at `/data/audits`.
- `covered-on-screaming-frog-home` stores Screaming Frog configuration and runtime state.
- The container runs as UID/GID `10001`, with a read-only root filesystem. Runtime writes are limited to the named volumes and tmpfs mounts.
- Stop the report service without deleting data with `docker compose down`. Delete persisted data only when it is no longer needed: `docker volume rm covered-on-seo-audit-data covered-on-screaming-frog-home`.

### Security model

Compose drops all Linux capabilities and enables `no-new-privileges`. It does not publish a host port; connect it to an approved internal reverse proxy or inspect it with `docker compose exec`. The crawler still makes outbound requests to target sites, so validate and rate-limit URLs at the queue/API boundary before exposing the runner to untrusted submissions. The proprietary installer is not redistributed by this repository.

## Local development

Use the existing virtual environment and requirements workflow for local development. The container build is the reproducible deployment path:

```bash
poetry install
python pipeline.py https://example.com
```
