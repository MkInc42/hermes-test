# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm

ARG SCREAMING_FROG_DEB=screamingfrogseospider.deb

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/auditor \
    XDG_CONFIG_HOME=/home/auditor/.config \
    PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright \
    AUDIT_OUTPUT_DIR=/data/audits

# Install the package manager and the local Screaming Frog package; cleanup keeps
# apt metadata and the proprietary installer out of the final filesystem.
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY ${SCREAMING_FROG_DEB} /tmp/screamingfrogseospider.deb
RUN apt-get update \
    && apt-get install --no-install-recommends -y /tmp/screamingfrogseospider.deb \
    && rm -f /tmp/screamingfrogseospider.deb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml poetry.lock ./

# Poetry is pinned so dependency resolution is reproducible in CI and on hosts.
RUN pip install --no-cache-dir "poetry==2.4.1" \
    && poetry config virtualenvs.create false \
    && poetry install --only main --no-root \
    && python -m playwright install --with-deps chromium \
    && rm -rf /root/.cache/pip /root/.cache/ms-playwright

RUN groupadd --gid 10001 auditor \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin auditor \
    && mkdir -p /data/audits /home/auditor/.ScreamingFrogSEOSpider /home/auditor/.config /home/auditor/.cache \
    && chown -R 10001:10001 /data /home/auditor

COPY --chown=10001:10001 . /app/

USER 10001:10001

VOLUME ["/data/audits", "/home/auditor/.ScreamingFrogSEOSpider"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=45s --retries=3 \
    CMD ["python", "/app/healthcheck.py"]

# Keep `up` safe: serve existing reports rather than unexpectedly crawling a site.
CMD ["python", "-m", "http.server", "8000", "--bind", "0.0.0.0", "--directory", "/data/audits"]
