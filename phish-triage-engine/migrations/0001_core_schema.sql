-- Migration 0001: core persistence schema for the phishing triage engine.
--
-- Design rules (from BACKEND_INPUT_THREAT_MODEL.md):
--   * Every analyzable record is tenant-scoped from day one: the tenant_uid
--     column is NOT NULL on all business tables and is part of every FK so a
--     row cannot exist without a valid tenant, and cross-tenant joins are
--     structurally impossible (composite FKs).
--   * Original artifacts are immutable: updates to artifact bytes/hashes are
--     rejected by trigger; corrections create new derived artifacts.
--   * Postgres identity columns are used for internal ordering keys while
--     UUIDs are the external reference IDs surfaced in reports/APIs.

-- UUID generation without requiring an extension load per database (pgcrypto
-- ships with Postgres 13+ contrib; gen_random_uuid() is core since PG13).
CREATE TABLE tenants (
    tenant_uid     TEXT PRIMARY KEY,
    display_name   TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'active'
                       CHECK (status IN ('active', 'suspended', 'deleted')),
    retention_tier TEXT NOT NULL DEFAULT 'standard',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE submissions (
    submission_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_uid        TEXT NOT NULL REFERENCES tenants (tenant_uid),
    source_type       TEXT NOT NULL
                          CHECK (source_type IN ('raw_url', 'email_artifact',
                                                 'ocr_text_message',
                                                 'screenshot_evidence',
                                                 'mixed_bundle')),
    submitted_by_type TEXT NOT NULL
                          CHECK (submitted_by_type IN ('internal_analyst',
                                                       'customer_delegate',
                                                       'automation')),
    submitted_by_name TEXT,
    submitted_by_contact TEXT,
    case_reference    TEXT,
    customer_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Consent/authorization flags are mandatory at intake; a submission that
    -- failed validation is retained as evidence of a rejected attempt.
    consent_authorized     BOOLEAN NOT NULL,
    consent_no_credentials BOOLEAN NOT NULL,
    validation_status      TEXT NOT NULL DEFAULT 'pending'
                               CHECK (validation_status IN ('pending', 'accepted',
                                                            'rejected', 'quarantined')),
    rejection_reason       TEXT,
    -- Fidelity labeling: copy/paste email without full headers is lower
    -- confidence and must carry that caveat into reports.
    fidelity               TEXT NOT NULL DEFAULT 'full'
                               CHECK (fidelity IN ('full', 'partial', 'low')),
    fidelity_notes         TEXT,
    submitted_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_submissions_tenant ON submissions (tenant_uid, submitted_at DESC);

ALTER TABLE submissions ADD CONSTRAINT uq_submissions_tenant_scope
    UNIQUE (submission_id, tenant_uid);

-- Envelope JSON as received from the client, stored verbatim for evidence.
CREATE TABLE submission_envelopes (
    submission_id UUID PRIMARY KEY,
    tenant_uid    TEXT NOT NULL REFERENCES tenants (tenant_uid),
    envelope      JSONB NOT NULL,
    received_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (submission_id, tenant_uid)
        REFERENCES submissions (submission_id, tenant_uid) ON DELETE CASCADE
);

CREATE TABLE jobs (
    job_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_uid        TEXT NOT NULL REFERENCES tenants (tenant_uid),
    submission_id     UUID NOT NULL,
    source_type       TEXT NOT NULL,
    state             TEXT NOT NULL DEFAULT 'submitted'
                          CHECK (state IN ('submitted', 'validated', 'queued',
                                           'normalizing', 'policy_checked',
                                           'scanning', 'analyzing', 'reporting',
                                           'completed', 'blocked', 'failed',
                                           'expired')),
    -- Policy decisions recorded at intake/policy gate (e.g. scheme allowlist).
    policy_decisions  JSONB NOT NULL DEFAULT '{}'::jsonb,
    priority          INTEGER NOT NULL DEFAULT 5,
    queued_at         TIMESTAMPTZ,
    started_at        TIMESTAMPTZ,
    finished_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (submission_id, tenant_uid)
        REFERENCES submissions (submission_id, tenant_uid)
);

-- Uniqueness: one active job per submission; re-analysis creates a new
-- submission (immutability rule) rather than re-using the job record.
CREATE UNIQUE INDEX uq_jobs_submission_active ON jobs (submission_id)
    WHERE state NOT IN ('failed', 'expired');

CREATE INDEX idx_jobs_tenant_state ON jobs (tenant_uid, state);

-- Composite FK helper: every child of jobs must be same-tenant. A proper
-- UNIQUE CONSTRAINT (not just a unique index) is required so Postgres allows
-- FOREIGN KEY (job_id, tenant_uid) REFERENCES jobs (job_id, tenant_uid).
ALTER TABLE jobs ADD CONSTRAINT uq_jobs_tenant_scope UNIQUE (job_id, tenant_uid);
ALTER TABLE jobs ADD CONSTRAINT uq_jobs_submission_tenant_scope
    UNIQUE (job_id, submission_id, tenant_uid);

CREATE TABLE input_artifacts (
    artifact_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_uid      TEXT NOT NULL REFERENCES tenants (tenant_uid),
    job_id          UUID NOT NULL,
    submission_id   UUID NOT NULL,
    artifact_kind   TEXT NOT NULL DEFAULT 'original'
                        CHECK (artifact_kind IN ('original', 'derived')),
    artifact_type   TEXT NOT NULL
                        CHECK (artifact_type IN ('eml', 'msg', 'raw_headers',
                                                 'forwarded_body', 'mime_text',
                                                 'screenshot', 'pdf', 'url_text',
                                                 'ocr_text')),
    original_filename TEXT,
    media_type      TEXT NOT NULL,
    sha256          CHAR(64) NOT NULL,
    byte_size       BIGINT NOT NULL CHECK (byte_size >= 0),
    storage_pointer TEXT NOT NULL,
    is_sensitive    BOOLEAN NOT NULL DEFAULT FALSE,
    captured_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      TEXT NOT NULL DEFAULT 'intake',
    FOREIGN KEY (job_id, submission_id, tenant_uid)
        REFERENCES jobs (job_id, submission_id, tenant_uid),
    UNIQUE (artifact_id, job_id, submission_id, tenant_uid)
);

-- Immutability of original artifacts: bytes/hash/pointer cannot change.
CREATE FUNCTION reject_artifact_mutation() RETURNS trigger AS $$
BEGIN
    IF NEW.sha256 IS DISTINCT FROM OLD.sha256
       OR NEW.storage_pointer IS DISTINCT FROM OLD.storage_pointer
       OR NEW.byte_size IS DISTINCT FROM OLD.byte_size THEN
        RAISE EXCEPTION 'input_artifacts are immutable; create a derived artifact instead';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_artifact_immutable
    BEFORE UPDATE ON input_artifacts
    FOR EACH ROW EXECUTE FUNCTION reject_artifact_mutation();

CREATE INDEX idx_input_artifacts_tenant_job ON input_artifacts (tenant_uid, job_id);

CREATE TABLE derived_artifacts (
    derived_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_uid     TEXT NOT NULL REFERENCES tenants (tenant_uid),
    job_id         UUID NOT NULL,
    submission_id  UUID NOT NULL,
    parent_artifact_id UUID,
    derived_kind   TEXT NOT NULL
                       CHECK (derived_kind IN ('parsed_headers', 'ocr_output',
                                               'screenshot_capture', 'http_transcript',
                                               'redirect_chain', 'dns_results',
                                               'dom_snapshot', 'har', 'report_file',
                                               'enrichment_payload')),
    media_type     TEXT NOT NULL,
    sha256         CHAR(64) NOT NULL,
    byte_size      BIGINT NOT NULL CHECK (byte_size >= 0),
    storage_pointer TEXT NOT NULL,
    produced_by    TEXT NOT NULL,        -- tool/container identity
    tool_version   TEXT,
    produced_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (job_id, submission_id, tenant_uid)
        REFERENCES jobs (job_id, submission_id, tenant_uid),
    FOREIGN KEY (parent_artifact_id, job_id, submission_id, tenant_uid)
        REFERENCES input_artifacts (artifact_id, job_id, submission_id, tenant_uid),
    UNIQUE (derived_id, job_id, tenant_uid)
);

CREATE INDEX idx_derived_artifacts_tenant_job ON derived_artifacts (tenant_uid, job_id);

CREATE TABLE indicators (
    indicator_id  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_uid    TEXT NOT NULL REFERENCES tenants (tenant_uid),
    job_id        UUID NOT NULL,
    indicator_type TEXT NOT NULL
                      CHECK (indicator_type IN ('url', 'domain', 'hostname', 'ip',
                                                'email_address', 'phone_number',
                                                'file_hash', 'qr_value')),
    raw_value     TEXT NOT NULL,
    -- Defanged form for report rendering (hxxp://, [.]) - raw preserved here.
    defanged_value TEXT,
    -- OCR-derived indicators must be labeled unless corroborated.
    provenance    TEXT NOT NULL DEFAULT 'parsed'
                      CHECK (provenance IN ('parsed', 'ocr_derived', 'analyst', 'scanner')),
    corroboration_status TEXT NOT NULL DEFAULT 'unverified'
                      CHECK (corroboration_status IN ('unverified', 'corroborated', 'contradicted')),
    confidence    NUMERIC(3, 2) CHECK (confidence BETWEEN 0 AND 1),
    extracted_by  TEXT NOT NULL DEFAULT 'intake',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (job_id, tenant_uid) REFERENCES jobs (job_id, tenant_uid),
    UNIQUE (tenant_uid, job_id, indicator_type, raw_value)
);

CREATE INDEX idx_indicators_tenant_job ON indicators (tenant_uid, job_id);
CREATE INDEX idx_indicators_value ON indicators (raw_value);

ALTER TABLE indicators ADD CONSTRAINT uq_indicators_job_tenant_scope
    UNIQUE (indicator_id, job_id, tenant_uid);

CREATE TABLE scan_events (
    event_id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_uid   TEXT NOT NULL REFERENCES tenants (tenant_uid),
    job_id       UUID NOT NULL,
    event_type   TEXT NOT NULL,
    actor        TEXT NOT NULL,           -- tool/container/worker identity
    route_label  TEXT NOT NULL DEFAULT 'direct-dev'
                     CHECK (route_label IN ('direct-dev', 'pia-sidecar-required',
                                            'blocked-no-route')),
    outcome      TEXT NOT NULL CHECK (outcome IN ('ok', 'error', 'blocked')),
    detail       JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (job_id, tenant_uid) REFERENCES jobs (job_id, tenant_uid)
);

CREATE INDEX idx_scan_events_tenant_job ON scan_events (tenant_uid, job_id, occurred_at);

-- Normalized per-job risk assessment; superseded scores are kept for history.
CREATE TABLE risk_scores (
    risk_score_id  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_uid     TEXT NOT NULL REFERENCES tenants (tenant_uid),
    job_id         UUID NOT NULL,
    classification TEXT NOT NULL
                       CHECK (classification IN ('benign', 'suspicious', 'phishing',
                                                 'malware_delivery',
                                                 'blocked_insufficient_evidence')),
    confidence     NUMERIC(3, 2) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    score          NUMERIC(5, 2) NOT NULL CHECK (score >= 0),
    factors        JSONB NOT NULL DEFAULT '{}'::jsonb,
    superseded_by  BIGINT REFERENCES risk_scores (risk_score_id),
    created_by     TEXT NOT NULL DEFAULT 'engine',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (job_id, tenant_uid) REFERENCES jobs (job_id, tenant_uid)
);

CREATE INDEX idx_risk_scores_tenant_job ON risk_scores (tenant_uid, job_id);

-- Composite FK helper: reports may only reference a risk score belonging to
-- the same tenant.
ALTER TABLE risk_scores ADD CONSTRAINT uq_risk_scores_tenant_scope
    UNIQUE (risk_score_id, job_id, tenant_uid);

CREATE TABLE reports (
    report_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_uid      TEXT NOT NULL REFERENCES tenants (tenant_uid),
    job_id          UUID NOT NULL,
    submission_id   UUID NOT NULL,
    report_version  INTEGER NOT NULL DEFAULT 1,
    audience        TEXT NOT NULL DEFAULT 'internal'
                        CHECK (audience IN ('internal', 'customer')),
    format          TEXT NOT NULL DEFAULT 'markdown'
                        CHECK (format IN ('markdown', 'html', 'pdf', 'json')),
    risk_score_id   BIGINT,
    executive_finding TEXT NOT NULL,
    -- Evidence manifest: artifact ids + hashes backing the report.
    evidence_manifest JSONB NOT NULL DEFAULT '{}'::jsonb,
    redaction_state TEXT NOT NULL DEFAULT 'redacted'
                        CHECK (redaction_state IN ('raw', 'redacted', 'customer_safe')),
    storage_pointer TEXT NOT NULL,
    sha256          CHAR(64) NOT NULL,
    generated_by    TEXT NOT NULL,
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (job_id, submission_id, tenant_uid)
        REFERENCES jobs (job_id, submission_id, tenant_uid),
    FOREIGN KEY (risk_score_id, job_id, tenant_uid)
        REFERENCES risk_scores (risk_score_id, job_id, tenant_uid)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE UNIQUE INDEX uq_reports_job_version ON reports (tenant_uid, job_id, report_version);

-- Normalized provider results. The optional indicator identifies a normalized
-- observable; observable_value also permits observations made before/without
-- indicator extraction. Raw provider output is retained as a derived artifact.
CREATE TABLE enrichment_observations (
    observation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_uid     TEXT NOT NULL REFERENCES tenants (tenant_uid),
    job_id         UUID NOT NULL,
    provider       TEXT NOT NULL CHECK (btrim(provider) <> ''),
    source         TEXT NOT NULL CHECK (btrim(source) <> ''),
    indicator_id   BIGINT,
    observable_value TEXT,
    result         JSONB NOT NULL DEFAULT '{}'::jsonb,
    status         TEXT NOT NULL
                       CHECK (status IN ('ok', 'not_found', 'unavailable',
                                         'blocked', 'error')),
    raw_artifact_id UUID,
    observed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (indicator_id IS NOT NULL OR COALESCE(btrim(observable_value), '') <> ''),
    FOREIGN KEY (job_id, tenant_uid) REFERENCES jobs (job_id, tenant_uid),
    FOREIGN KEY (indicator_id, job_id, tenant_uid)
        REFERENCES indicators (indicator_id, job_id, tenant_uid),
    FOREIGN KEY (raw_artifact_id, job_id, tenant_uid)
        REFERENCES derived_artifacts (derived_id, job_id, tenant_uid)
);

CREATE INDEX idx_enrichment_observations_tenant_job
    ON enrichment_observations (tenant_uid, job_id, observed_at);

CREATE TABLE source_status (
    source_status_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_uid       TEXT NOT NULL REFERENCES tenants (tenant_uid),
    job_id           UUID NOT NULL,
    source_type      TEXT NOT NULL,
    status           TEXT NOT NULL
                         CHECK (status IN ('received', 'parsed', 'scan_pending',
                                           'scanned', 'enriched', 'unreachable',
                                           'blocked', 'failed')),
    status_detail    JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (job_id, tenant_uid) REFERENCES jobs (job_id, tenant_uid),
    UNIQUE (tenant_uid, job_id, source_type)
);

CREATE TABLE audit_events (
    audit_id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_uid   TEXT NOT NULL,
    job_id       UUID,
    submission_id UUID,
    actor        TEXT NOT NULL,
    action       TEXT NOT NULL,
    target       TEXT,
    outcome      TEXT NOT NULL DEFAULT 'ok' CHECK (outcome IN ('ok', 'denied', 'error')),
    detail       JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (btrim(tenant_uid) <> '')
    -- Business-row references deliberately remain unkeyed so deleting jobs or
    -- submissions cannot delete their audit history. Tenant existence is
    -- checked by trigger at write time so deleting a tenant also preserves it.
);

CREATE INDEX idx_audit_events_tenant ON audit_events (tenant_uid, occurred_at DESC);

-- Defense in depth: refuse inserts/updates where tenant_uid is NULL/empty even
-- if a future migration relaxes a column constraint.
CREATE OR REPLACE FUNCTION enforce_tenant_uid() RETURNS trigger AS $$
BEGIN
    IF NEW.tenant_uid IS NULL OR btrim(NEW.tenant_uid) = '' THEN
        RAISE EXCEPTION 'tenant_uid is required on %', TG_TABLE_NAME;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Audit history deliberately has no tenant FK: validate the tenant while an
-- audit row is written, but do not let later tenant deletion erase or block
-- retention of the historical event.
CREATE OR REPLACE FUNCTION validate_audit_tenant_uid() RETURNS trigger AS $$
BEGIN
    IF NEW.tenant_uid IS NULL OR btrim(NEW.tenant_uid) = '' THEN
        RAISE EXCEPTION 'tenant_uid is required on audit_events';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM tenants WHERE tenant_uid = NEW.tenant_uid
    ) THEN
        RAISE EXCEPTION 'unknown tenant_uid on audit_events: %', NEW.tenant_uid;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_enforce_tenant_uid_submissions
    BEFORE INSERT OR UPDATE ON submissions
    FOR EACH ROW EXECUTE FUNCTION enforce_tenant_uid();
CREATE TRIGGER trg_enforce_tenant_uid_jobs
    BEFORE INSERT OR UPDATE ON jobs
    FOR EACH ROW EXECUTE FUNCTION enforce_tenant_uid();
CREATE TRIGGER trg_enforce_tenant_uid_input_artifacts
    BEFORE INSERT OR UPDATE ON input_artifacts
    FOR EACH ROW EXECUTE FUNCTION enforce_tenant_uid();
CREATE TRIGGER trg_enforce_tenant_uid_derived_artifacts
    BEFORE INSERT OR UPDATE ON derived_artifacts
    FOR EACH ROW EXECUTE FUNCTION enforce_tenant_uid();
CREATE TRIGGER trg_enforce_tenant_uid_indicators
    BEFORE INSERT OR UPDATE ON indicators
    FOR EACH ROW EXECUTE FUNCTION enforce_tenant_uid();
CREATE TRIGGER trg_enforce_tenant_uid_scan_events
    BEFORE INSERT OR UPDATE ON scan_events
    FOR EACH ROW EXECUTE FUNCTION enforce_tenant_uid();
CREATE TRIGGER trg_enforce_tenant_uid_risk_scores
    BEFORE INSERT OR UPDATE ON risk_scores
    FOR EACH ROW EXECUTE FUNCTION enforce_tenant_uid();
CREATE TRIGGER trg_enforce_tenant_uid_reports
    BEFORE INSERT OR UPDATE ON reports
    FOR EACH ROW EXECUTE FUNCTION enforce_tenant_uid();
CREATE TRIGGER trg_enforce_tenant_uid_source_status
    BEFORE INSERT OR UPDATE ON source_status
    FOR EACH ROW EXECUTE FUNCTION enforce_tenant_uid();
CREATE TRIGGER trg_enforce_tenant_uid_enrichment_observations
    BEFORE INSERT OR UPDATE ON enrichment_observations
    FOR EACH ROW EXECUTE FUNCTION enforce_tenant_uid();
CREATE TRIGGER trg_enforce_tenant_uid_audit_events
    BEFORE INSERT OR UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION validate_audit_tenant_uid();
