"""Tenant-scoped persistence services for the triage engine.

All write paths live here so tenant enforcement is in exactly one place:
every function takes an explicit tenant_uid and re-checks scope on read,
and service functions refuse None/empty tenants structurally (keyword-only,
required). Routes in later cards orchestrate; business rules belong here.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from typing import Any

import psycopg
from psycopg.rows import dict_row

from .db import DbConfig, connect

# ---------------------------------------------------------------------------
# Errors


class PersistenceError(Exception):
    """Base error for the persistence layer."""


class TenantRequiredError(PersistenceError):
    """Raised when a tenant UID is missing, empty, or unknown."""


class CrossTenantAccessError(PersistenceError):
    """Raised when a record lookup is not visible under the given tenant."""


class ValidationError(PersistenceError):
    """Raised when a record fails field-level checks before hitting the DB."""


def require_tenant(tenant_uid: str | None) -> str:
    """Validate that a tenant UID is present and well-formed.

    Every service call routes through this so a tenantless write is a
    programming error, not silently stored data.
    """
    if not tenant_uid or not isinstance(tenant_uid, str) or not tenant_uid.strip():
        raise TenantRequiredError("tenant_uid is required for every persisted record")
    return tenant_uid.strip()


# ---------------------------------------------------------------------------
# Tenants


def ensure_tenant(cfg: DbConfig, tenant_uid: str, display_name: str) -> dict[str, Any]:
    """Create (or return existing) tenant. Idempotent for local setup/tests."""
    require_tenant(tenant_uid)
    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO tenants (tenant_uid, display_name)
            VALUES (%s, %s)
            ON CONFLICT (tenant_uid) DO UPDATE SET display_name = EXCLUDED.display_name
            RETURNING tenant_uid, display_name, status, retention_tier, created_at
            """,
            (tenant_uid, display_name),
        )
        row = cur.fetchone()
        conn.commit()
        return dict(row)


def get_tenant(cfg: DbConfig, tenant_uid: str) -> dict[str, Any] | None:
    require_tenant(tenant_uid)
    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT tenant_uid, display_name, status, retention_tier, created_at"
            " FROM tenants WHERE tenant_uid = %s",
            (tenant_uid,),
        )
        row = cur.fetchone()
        return dict(row) if row else None


# ---------------------------------------------------------------------------
# Submissions and jobs


def create_submission(
    cfg: DbConfig,
    tenant_uid: str,
    source_type: str,
    submitted_by_type: str = "internal_analyst",
    submitted_by_name: str | None = None,
    submitted_by_contact: str | None = None,
    case_reference: str | None = None,
    customer_metadata: dict[str, Any] | None = None,
    consent_authorized: bool = True,
    consent_no_credentials: bool = True,
    fidelity: str = "full",
    fidelity_notes: str | None = None,
    envelope: dict[str, Any] | None = None,
    validation_status: str = "accepted",
    rejection_reason: str | None = None,
) -> dict[str, Any]:
    """Persist a submission (and its raw envelope) under a tenant.

    Consent flags are stored verbatim: a rejected/quarantined intake keeps
    evidence of the attempt without ever producing an analyzable job.
    """
    require_tenant(tenant_uid)
    if source_type not in {"raw_url", "email_artifact", "ocr_text_message",
                           "screenshot_evidence", "mixed_bundle"}:
        raise ValidationError(f"invalid source_type: {source_type!r}")
    if fidelity not in {"full", "partial", "low"}:
        raise ValidationError(f"invalid fidelity: {fidelity!r}")

    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO submissions (
                tenant_uid, source_type, submitted_by_type, submitted_by_name,
                submitted_by_contact, case_reference, customer_metadata,
                consent_authorized, consent_no_credentials, validation_status,
                rejection_reason, fidelity, fidelity_notes
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING submission_id, tenant_uid, source_type, validation_status,
                      fidelity, submitted_at
            """,
            (
                tenant_uid, source_type, submitted_by_type, submitted_by_name,
                submitted_by_contact, case_reference,
                json.dumps(customer_metadata or {}), consent_authorized,
                consent_no_credentials, validation_status, rejection_reason,
                fidelity, fidelity_notes,
            ),
        )
        row = dict(cur.fetchone())
        if envelope is not None:
            cur.execute(
                """
                INSERT INTO submission_envelopes (submission_id, tenant_uid, envelope)
                VALUES (%s, %s, %s)
                """,
                (row["submission_id"], tenant_uid, json.dumps(envelope)),
            )
        conn.commit()
        return row


def create_job(
    cfg: DbConfig,
    tenant_uid: str,
    submission_id: uuid.UUID | str,
    source_type: str,
    policy_decisions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a scan job for an accepted submission.

    The job FK chain (submission -> tenant) guarantees the submission belongs
    to the same tenant; the composite (job_id, tenant_uid) key then scopes
    every artifact/event/report child row.
    """
    require_tenant(tenant_uid)
    if source_type not in {"raw_url", "email_artifact", "ocr_text_message",
                           "screenshot_evidence", "mixed_bundle"}:
        raise ValidationError(f"invalid source_type: {source_type!r}")
    with connect(cfg) as conn, conn.cursor() as cur:
        # Tenant check up front: never allow a job to attach across tenants.
        cur.execute(
            "SELECT source_type, validation_status FROM submissions"
            " WHERE submission_id = %s AND tenant_uid = %s",
            (submission_id, tenant_uid),
        )
        sub = cur.fetchone()
        if sub is None:
            raise CrossTenantAccessError(
                f"submission {submission_id} not found under tenant {tenant_uid}"
            )
        if sub["validation_status"] != "accepted":
            raise ValidationError("jobs require an accepted submission")
        if source_type != sub["source_type"]:
            raise ValidationError("job source_type must match its submission")
        cur.execute(
            """
            INSERT INTO jobs (tenant_uid, submission_id, source_type, state,
                              policy_decisions, queued_at)
            VALUES (%s, %s, %s, 'queued', %s, now())
            RETURNING job_id, tenant_uid, submission_id, source_type, state, queued_at
            """,
            (tenant_uid, submission_id, source_type, json.dumps(policy_decisions or {})),
        )
        row = dict(cur.fetchone())
        conn.commit()
        return row


def set_job_state(
    cfg: DbConfig,
    tenant_uid: str,
    job_id: uuid.UUID | str,
    state: str,
    actor: str = "engine",
    reason: str | None = None,
) -> dict[str, Any]:
    """Transition a job's lifecycle state and log the transition as an audit event.

    The spec requires each transition to record timestamp/actor/reason under
    tenant scope; audit_events is that record.
    """
    require_tenant(tenant_uid)
    allowed = {"submitted", "validated", "queued", "normalizing", "policy_checked",
               "scanning", "analyzing", "reporting", "completed", "blocked",
               "failed", "expired"}
    if state not in allowed:
        raise ValidationError(f"invalid job state: {state!r}")
    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE jobs SET state = %s,
                            started_at = COALESCE(started_at, CASE WHEN %s IN
                                ('normalizing','scanning') THEN now() END),
                            finished_at = CASE WHEN %s IN
                                ('completed','blocked','failed','expired') THEN now() END
            WHERE job_id = %s AND tenant_uid = %s
            RETURNING job_id, state, started_at, finished_at
            """,
            (state, state, state, job_id, tenant_uid),
        )
        row = cur.fetchone()
        if row is None:
            raise CrossTenantAccessError(
                f"job {job_id} not found under tenant {tenant_uid}"
            )
        cur.execute(
            """
            INSERT INTO audit_events (tenant_uid, job_id, actor, action, outcome, detail)
            VALUES (%s, %s, %s, %s, 'ok', %s)
            """,
            (tenant_uid, job_id, actor, f"job_state:{state}", json.dumps({"reason": reason})),
        )
        conn.commit()
        return dict(row)


def claim_queued_job(
    cfg: DbConfig,
    *,
    tenant_uid: str,
    actor: str = "pipeline-worker",
) -> dict[str, Any] | None:
    """Atomically claim the next queued job for one tenant.

    ``SKIP LOCKED`` lets multiple worker processes poll safely.  Moving the row
    to ``normalizing`` in the same transaction makes the claim durable before
    any artifact work starts, so a job cannot be processed twice.
    """
    tenant_uid = require_tenant(tenant_uid)
    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute(
            """
            WITH candidate AS (
                SELECT job_id
                FROM jobs
                WHERE tenant_uid = %s AND state = 'queued'
                ORDER BY priority ASC, queued_at ASC, created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            UPDATE jobs AS j
            SET state = 'normalizing', started_at = COALESCE(started_at, now())
            FROM candidate
            WHERE j.job_id = candidate.job_id AND j.tenant_uid = %s
            RETURNING j.job_id, j.tenant_uid, j.submission_id, j.source_type,
                      j.state, j.policy_decisions, j.started_at
            """,
            (tenant_uid, tenant_uid),
        )
        row = cur.fetchone()
        if row is None:
            conn.commit()
            return None
        cur.execute(
            """INSERT INTO audit_events
               (tenant_uid,job_id,actor,action,outcome,detail)
               VALUES (%s,%s,%s,'job_state:normalizing','ok',%s)""",
            (tenant_uid, row["job_id"], actor,
             json.dumps({"reason_code": "queue_claimed"})),
        )
        conn.commit()
        return dict(row)


def record_job_failure(
    cfg: DbConfig,
    *,
    tenant_uid: str,
    job_id: uuid.UUID | str,
    status: str,
    reason_code: str,
    actor: str = "pipeline-worker",
) -> dict[str, Any]:
    """Record a redacted terminal pipeline outcome without exception text."""
    tenant_uid = require_tenant(tenant_uid)
    if status not in {"blocked", "failed"}:
        raise ValidationError("pipeline failure status must be blocked or failed")
    if (not isinstance(reason_code, str) or not reason_code or len(reason_code) > 80
            or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for ch in reason_code)):
        raise ValidationError("pipeline reason_code must be a conservative identifier")
    detail = {"reason_code": reason_code, "terminal_status": status, "retryable": True}
    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE jobs SET state=%s,finished_at=now()"
            " WHERE job_id=%s AND tenant_uid=%s"
            " AND state NOT IN ('completed','blocked','failed','expired')"
            " RETURNING job_id,state,finished_at",
            (status, job_id, tenant_uid),
        )
        row = cur.fetchone()
        if row is None:
            raise ValidationError("pipeline failure requires a nonterminal job")
        cur.execute(
            """INSERT INTO audit_events
               (tenant_uid,job_id,actor,action,outcome,detail)
               VALUES (%s,%s,%s,%s,%s,%s)""",
            (tenant_uid, job_id, actor, f"job_state:{status}",
             "denied" if status == "blocked" else "error", json.dumps(detail)),
        )
        conn.commit()
        return dict(row)


def requeue_terminal_job(
    cfg: DbConfig, *, tenant_uid: str, job_id: uuid.UUID | str,
    actor: str = "pipeline-operator",
) -> dict[str, Any]:
    """Explicitly retry one failed/blocked job; completed jobs are immutable."""
    tenant_uid = require_tenant(tenant_uid)
    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute(
            """UPDATE jobs SET state='queued',queued_at=now(),started_at=NULL,finished_at=NULL
               WHERE job_id=%s AND tenant_uid=%s AND state IN ('failed','blocked')
               RETURNING job_id,state,queued_at""",
            (job_id, tenant_uid),
        )
        row = cur.fetchone()
        if row is None:
            raise ValidationError("only failed or blocked jobs can be requeued")
        cur.execute(
            """INSERT INTO audit_events
               (tenant_uid,job_id,actor,action,outcome,detail)
               VALUES (%s,%s,%s,'job_state:queued','ok',%s)""",
            (tenant_uid, job_id, actor,
             json.dumps({"reason_code": "operator_retry"})),
        )
        conn.commit()
        return dict(row)


# ---------------------------------------------------------------------------
# Artifacts


def compute_sha256(data: bytes) -> str:
    """SHA-256 of exact bytes (chain-of-custody hash)."""
    return hashlib.sha256(data).hexdigest()


def create_intake_bundle(
    cfg: DbConfig,
    *,
    tenant_uid: str,
    source_type: str,
    fidelity: str,
    fidelity_notes: str | None,
    envelope: dict[str, Any],
    policy_decisions: dict[str, Any],
    artifacts: list[dict[str, Any]],
    derived_artifacts: list[dict[str, Any]] | None = None,
    indicators: list[dict[str, Any]] | None = None,
    storage_writer: Callable[[str, bytes], str],
    consent_authorized: bool,
    consent_no_credentials: bool,
) -> dict[str, Any]:
    """Atomically persist an accepted intake, job, artifacts, and indicators.

    Blob writes happen before their referencing rows. On any error the database
    transaction rolls back; content-addressed orphan blobs are harmless and may
    be reused by a retry.
    """
    tenant_uid = require_tenant(tenant_uid)
    if not consent_authorized or not consent_no_credentials:
        raise ValidationError("authorization and no-credentials attestations are required")
    if source_type not in {"raw_url", "email_artifact", "ocr_text_message", "screenshot_evidence"}:
        raise ValidationError(f"invalid source_type: {source_type!r}")
    if fidelity not in {"full", "partial", "low"}:
        raise ValidationError(f"invalid fidelity: {fidelity!r}")

    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute("SELECT status FROM tenants WHERE tenant_uid = %s FOR SHARE", (tenant_uid,))
        tenant = cur.fetchone()
        if tenant is None:
            raise TenantRequiredError("unknown tenant_uid")
        if tenant["status"] != "active":
            raise TenantRequiredError("tenant is not active")
        stored = [(item, storage_writer(tenant_uid, item["data"])) for item in artifacts]
        derived_stored = [
            (item, storage_writer(tenant_uid, item["data"]))
            for item in (derived_artifacts or [])
        ]
        cur.execute(
            """INSERT INTO submissions
               (tenant_uid, source_type, submitted_by_type, consent_authorized,
                consent_no_credentials, validation_status, fidelity, fidelity_notes)
               VALUES (%s,%s,'customer_delegate',TRUE,TRUE,'accepted',%s,%s)
               RETURNING submission_id, tenant_uid, source_type, validation_status, fidelity""",
            (tenant_uid, source_type, fidelity, fidelity_notes),
        )
        submission = dict(cur.fetchone())
        cur.execute(
            "INSERT INTO submission_envelopes (submission_id, tenant_uid, envelope) VALUES (%s,%s,%s)",
            (submission["submission_id"], tenant_uid, json.dumps(envelope)),
        )
        cur.execute(
            """INSERT INTO jobs (tenant_uid, submission_id, source_type, state,
                                  policy_decisions, queued_at)
               VALUES (%s,%s,%s,'queued',%s,now())
               RETURNING job_id, submission_id, source_type, state""",
            (tenant_uid, submission["submission_id"], source_type, json.dumps(policy_decisions)),
        )
        job = dict(cur.fetchone())
        artifact_rows = []
        derived_rows = []
        artifact_ids: dict[str, Any] = {}
        for item, pointer in stored:
            cur.execute(
                """INSERT INTO input_artifacts
                   (tenant_uid,job_id,submission_id,artifact_kind,artifact_type,
                    original_filename,media_type,sha256,byte_size,storage_pointer,is_sensitive)
                   VALUES (%s,%s,%s,'original',%s,%s,%s,%s,%s,%s,%s)
                   RETURNING artifact_id,artifact_type,media_type,sha256,byte_size""",
                (tenant_uid, job["job_id"], submission["submission_id"],
                 item["artifact_type"], item.get("original_filename"), item["media_type"],
                 compute_sha256(item["data"]), len(item["data"]), pointer,
                 item.get("is_sensitive", True)),
            )
            row = dict(cur.fetchone())
            artifact_rows.append(row)
            if item.get("key"):
                artifact_ids[item["key"]] = row["artifact_id"]
        for item, pointer in derived_stored:
            cur.execute(
                """INSERT INTO derived_artifacts
                   (tenant_uid,job_id,submission_id,parent_artifact_id,derived_kind,
                    media_type,sha256,byte_size,storage_pointer,produced_by,tool_version)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'intake-parser','stdlib')
                   RETURNING derived_id,parent_artifact_id,derived_kind,media_type,sha256,byte_size""",
                (tenant_uid, job["job_id"], submission["submission_id"],
                 artifact_ids.get(item.get("parent_key")), item["derived_kind"],
                 item["media_type"], compute_sha256(item["data"]), len(item["data"]), pointer),
            )
            derived_rows.append(dict(cur.fetchone()))
        for item in indicators or []:
            cur.execute(
                """INSERT INTO indicators
                   (tenant_uid,job_id,indicator_type,raw_value,defanged_value,provenance,
                    corroboration_status,confidence,extracted_by)
                   VALUES (%s,%s,%s,%s,%s,%s,'unverified',%s,'intake')
                   ON CONFLICT (tenant_uid,job_id,indicator_type,raw_value) DO NOTHING""",
                (tenant_uid, job["job_id"], item["indicator_type"], item["raw_value"],
                 item.get("defanged_value"), item.get("provenance", "parsed"),
                 item.get("confidence")),
            )
        conn.commit()
    return {"submission": submission, "job": job, "artifacts": artifact_rows,
            "derived_artifacts": derived_rows}


def add_input_artifact(
    cfg: DbConfig,
    tenant_uid: str,
    job_id: uuid.UUID | str,
    submission_id: uuid.UUID | str,
    artifact_type: str,
    media_type: str,
    data: bytes,
    storage_pointer: str,
    original_filename: str | None = None,
    is_sensitive: bool = False,
    created_by: str = "intake",
) -> dict[str, Any]:
    """Store an immutable original artifact record with its SHA-256 hash."""
    require_tenant(tenant_uid)
    if artifact_type not in {"eml", "msg", "raw_headers", "forwarded_body",
                             "mime_text", "screenshot", "pdf", "url_text", "ocr_text"}:
        raise ValidationError(f"invalid artifact_type: {artifact_type!r}")
    with connect(cfg) as conn, conn.cursor() as cur:
        # Validate the complete chain so callers get a stable service error;
        # the composite FK remains the raw-SQL backstop.
        cur.execute(
            "SELECT 1 FROM jobs WHERE job_id = %s AND tenant_uid = %s"
            " AND submission_id = %s",
            (job_id, tenant_uid, submission_id),
        )
        if cur.fetchone() is None:
            raise CrossTenantAccessError(
                f"job {job_id} and submission {submission_id} are not linked"
            )
        cur.execute(
            """
            INSERT INTO input_artifacts (
                tenant_uid, job_id, submission_id, artifact_kind, artifact_type,
                original_filename, media_type, sha256, byte_size, storage_pointer,
                is_sensitive, created_by
            ) VALUES (%s, %s, %s, 'original', %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING artifact_id, tenant_uid, job_id, artifact_type, sha256, byte_size
            """,
            (
                tenant_uid, job_id, submission_id, artifact_type, original_filename,
                media_type, compute_sha256(data), len(data), storage_pointer,
                is_sensitive, created_by,
            ),
        )
        row = dict(cur.fetchone())
        conn.commit()
        return row


def add_derived_artifact(
    cfg: DbConfig,
    tenant_uid: str,
    job_id: uuid.UUID | str,
    submission_id: uuid.UUID | str,
    derived_kind: str,
    media_type: str,
    data: bytes,
    storage_pointer: str,
    produced_by: str,
    tool_version: str | None = None,
    parent_artifact_id: uuid.UUID | str | None = None,
) -> dict[str, Any]:
    """Store a derived artifact (parsed headers, OCR output, report file, ...)."""
    require_tenant(tenant_uid)
    allowed = {"parsed_headers", "ocr_output", "screenshot_capture", "http_transcript",
               "redirect_chain", "dns_results", "dom_snapshot", "har", "report_file",
               "enrichment_payload"}
    if derived_kind not in allowed:
        raise ValidationError(f"invalid derived_kind: {derived_kind!r}")
    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM jobs WHERE job_id = %s AND tenant_uid = %s"
            " AND submission_id = %s",
            (job_id, tenant_uid, submission_id),
        )
        if cur.fetchone() is None:
            raise CrossTenantAccessError(
                f"job {job_id} and submission {submission_id} are not linked"
            )
        if parent_artifact_id is not None:
            cur.execute(
                "SELECT 1 FROM input_artifacts WHERE artifact_id = %s"
                " AND job_id = %s AND submission_id = %s AND tenant_uid = %s",
                (parent_artifact_id, job_id, submission_id, tenant_uid),
            )
            if cur.fetchone() is None:
                raise CrossTenantAccessError(
                    f"parent artifact {parent_artifact_id} is outside the job scope"
                )
        cur.execute(
            """
            INSERT INTO derived_artifacts (
                tenant_uid, job_id, submission_id, parent_artifact_id, derived_kind,
                media_type, sha256, byte_size, storage_pointer, produced_by, tool_version
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING derived_id, tenant_uid, job_id, derived_kind, sha256, byte_size
            """,
            (
                tenant_uid, job_id, submission_id, parent_artifact_id, derived_kind,
                media_type, compute_sha256(data), len(data), storage_pointer,
                produced_by, tool_version,
            ),
        )
        row = dict(cur.fetchone())
        conn.commit()
        return row


# ---------------------------------------------------------------------------
# Indicators


def add_indicators(
    cfg: DbConfig,
    tenant_uid: str,
    job_id: uuid.UUID | str,
    indicators: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Bulk-insert normalized indicators (URLs, domains, IPs, hashes, ...).

    Each item needs at least indicator_type + raw_value. OCR-derived items
    must set provenance='ocr_derived' so reports can label them.
    """
    require_tenant(tenant_uid)
    if not indicators:
        return []
    rows: list[dict[str, Any]] = []
    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM jobs WHERE job_id = %s AND tenant_uid = %s",
            (job_id, tenant_uid),
        )
        if cur.fetchone() is None:
            raise CrossTenantAccessError(
                f"job {job_id} not found under tenant {tenant_uid}"
            )
        for item in indicators:
            itype = item.get("indicator_type")
            raw = item.get("raw_value")
            if itype not in {"url", "domain", "hostname", "ip", "email_address",
                             "phone_number", "file_hash", "qr_value"}:
                raise ValidationError(f"invalid indicator_type: {itype!r}")
            if not raw or not isinstance(raw, str):
                raise ValidationError("indicator raw_value must be a non-empty string")
            cur.execute(
                """
                INSERT INTO indicators (
                    tenant_uid, job_id, indicator_type, raw_value, defanged_value,
                    provenance, corroboration_status, confidence, extracted_by
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_uid, job_id, indicator_type, raw_value)
                DO UPDATE SET confidence = EXCLUDED.confidence
                RETURNING indicator_id, indicator_type, raw_value, provenance
                """,
                (
                    tenant_uid, job_id, itype, raw, item.get("defanged_value"),
                    item.get("provenance", "parsed"),
                    item.get("corroboration_status", "unverified"),
                    item.get("confidence"), item.get("extracted_by", "intake"),
                ),
            )
            rows.append(dict(cur.fetchone()))
        conn.commit()
        return rows


# ---------------------------------------------------------------------------
# Scan events, enrichment observations, risk scores, reports, source status


def add_scan_event(
    cfg: DbConfig,
    tenant_uid: str,
    job_id: uuid.UUID | str,
    event_type: str,
    actor: str,
    outcome: str = "ok",
    route_label: str = "direct-dev",
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Record a scanner action/error/blocked-action with route provenance."""
    require_tenant(tenant_uid)
    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM jobs WHERE job_id = %s AND tenant_uid = %s",
            (job_id, tenant_uid),
        )
        if cur.fetchone() is None:
            raise CrossTenantAccessError(
                f"job {job_id} not found under tenant {tenant_uid}"
            )
        cur.execute(
            """
            INSERT INTO scan_events (tenant_uid, job_id, event_type, actor,
                                     route_label, outcome, detail)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING event_id, event_type, outcome, occurred_at
            """,
            (tenant_uid, job_id, event_type, actor, route_label, outcome,
             json.dumps(detail or {})),
        )
        row = dict(cur.fetchone())
        conn.commit()
        return row


def persist_scan_completion(
    cfg: DbConfig,
    *,
    tenant_uid: str,
    job_id: uuid.UUID | str,
    submission_id: uuid.UUID | str,
    route_label: str,
    policy: dict[str, Any],
    artifacts: list[dict[str, Any]],
    storage_writer: Callable[[str, bytes], str],
    actor: str = "scanner-runner",
    completion_state: str = "completed",
) -> dict[str, Any]:
    """Atomically link completed scan output and finish its tenant-scoped job.

    Blob writes precede database references.  A storage or SQL error leaves no
    completed job or partial database evidence; content-addressed blobs from a
    rolled-back attempt are safe, immutable retry candidates.
    """
    tenant_uid = require_tenant(tenant_uid)
    if completion_state not in {"completed", "analyzing"}:
        raise ValidationError("scan completion state must be completed or analyzing")
    if route_label not in {"direct-dev", "pia-sidecar-required"}:
        raise ValidationError("completed scans require an approved route label")
    allowed_kinds = {"screenshot_capture", "http_transcript", "redirect_chain",
                     "dns_results", "dom_snapshot", "har", "enrichment_payload"}
    if not artifacts:
        raise ValidationError("a completed scan requires artifacts")
    for item in artifacts:
        if item.get("derived_kind") not in allowed_kinds:
            raise ValidationError(f"invalid scan artifact kind: {item.get('derived_kind')!r}")
        if not isinstance(item.get("data"), bytes):
            raise ValidationError("scan artifact data must be bytes")
    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT state, source_type FROM jobs WHERE job_id = %s AND tenant_uid = %s"
            " AND submission_id = %s FOR UPDATE",
            (job_id, tenant_uid, submission_id),
        )
        job = cur.fetchone()
        if job is None:
            raise CrossTenantAccessError(
                f"job {job_id} and submission {submission_id} are not linked"
            )
        if job["state"] != "scanning":
            raise ValidationError("scan completion requires a job in scanning state")
        stored = [(item, storage_writer(tenant_uid, item["data"])) for item in artifacts]
        rows: list[dict[str, Any]] = []
        for item, pointer in stored:
            cur.execute(
                """
                INSERT INTO derived_artifacts (
                    tenant_uid, job_id, submission_id, derived_kind, media_type,
                    sha256, byte_size, storage_pointer, produced_by, tool_version
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                RETURNING derived_id, derived_kind, sha256, byte_size, storage_pointer
                """,
                (tenant_uid, job_id, submission_id, item["derived_kind"],
                 item["media_type"], compute_sha256(item["data"]), len(item["data"]),
                 pointer, actor, item.get("tool_version", "contract-v1")),
            )
            rows.append(dict(cur.fetchone()))
        detail = {"policy": policy, "artifact_count": len(rows),
                  "artifact_hashes": [row["sha256"] for row in rows]}
        cur.execute(
            """INSERT INTO scan_events
               (tenant_uid,job_id,event_type,actor,route_label,outcome,detail)
               VALUES (%s,%s,'scan_completed',%s,%s,'ok',%s)
               RETURNING event_id,event_type,outcome,occurred_at""",
            (tenant_uid, job_id, actor, route_label, json.dumps(detail)),
        )
        event = dict(cur.fetchone())
        cur.execute(
            """INSERT INTO source_status
               (tenant_uid,job_id,source_type,status,status_detail)
               VALUES (%s,%s,%s,'scanned',%s)
               ON CONFLICT (tenant_uid,job_id,source_type)
               DO UPDATE SET status='scanned',status_detail=EXCLUDED.status_detail,updated_at=now()""",
            (tenant_uid, job_id, job["source_type"], json.dumps(detail)),
        )
        cur.execute(
            "UPDATE jobs SET state=%s,finished_at=CASE WHEN %s='completed' THEN now() ELSE NULL END"
            " WHERE job_id=%s AND tenant_uid=%s",
            (completion_state, completion_state, job_id, tenant_uid),
        )
        cur.execute(
            """INSERT INTO audit_events
               (tenant_uid,job_id,actor,action,outcome,detail)
               VALUES (%s,%s,%s,%s,'ok',%s)""",
            (tenant_uid, job_id, actor, f"job_state:{completion_state}",
             json.dumps({"reason": "scan artifacts persisted"})),
        )
        conn.commit()
        return {"artifacts": rows, "event": event, "state": completion_state}


def persist_scan_failure(
    cfg: DbConfig,
    *,
    tenant_uid: str,
    job_id: uuid.UUID | str,
    submission_id: uuid.UUID | str,
    status: str,
    reason_code: str,
    route_label: str,
    actor: str = "scanner-runner",
) -> dict[str, Any]:
    """Atomically persist a terminal scanner failure under the job's tenant.

    Failure details are deliberately constrained to an operator-safe reason
    code. Exception strings can contain URLs, subprocess output, or secrets and
    therefore must not be copied into durable events.
    """
    tenant_uid = require_tenant(tenant_uid)
    if status not in {"blocked", "failed"}:
        raise ValidationError("scanner failure status must be blocked or failed")
    if route_label not in {"direct-dev", "pia-sidecar-required", "blocked-no-route"}:
        raise ValidationError("scanner failure requires an approved route label")
    if (not isinstance(reason_code, str) or not reason_code
            or len(reason_code) > 80
            or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_-"
                   for character in reason_code)):
        raise ValidationError("scanner reason_code must be a conservative identifier")
    detail = {"reason_code": reason_code, "terminal_status": status}
    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT state,source_type FROM jobs WHERE job_id=%s AND tenant_uid=%s"
            " AND submission_id=%s FOR UPDATE",
            (job_id, tenant_uid, submission_id),
        )
        job = cur.fetchone()
        if job is None:
            raise CrossTenantAccessError(
                f"job {job_id} and submission {submission_id} are not linked"
            )
        if job["state"] in {"completed", "blocked", "failed", "expired"}:
            raise ValidationError("scanner failure requires a nonterminal job")
        cur.execute(
            "UPDATE jobs SET state=%s,finished_at=now()"
            " WHERE job_id=%s AND tenant_uid=%s",
            (status, job_id, tenant_uid),
        )
        cur.execute(
            """INSERT INTO scan_events
               (tenant_uid,job_id,event_type,actor,route_label,outcome,detail)
               VALUES (%s,%s,%s,%s,%s,%s,%s)
               RETURNING event_id,event_type,outcome,occurred_at""",
            (tenant_uid, job_id, f"scan_{status}", actor, route_label,
             status if status == "blocked" else "error", json.dumps(detail)),
        )
        event = dict(cur.fetchone())
        cur.execute(
            """INSERT INTO source_status
               (tenant_uid,job_id,source_type,status,status_detail)
               VALUES (%s,%s,%s,%s,%s)
               ON CONFLICT (tenant_uid,job_id,source_type)
               DO UPDATE SET status=EXCLUDED.status,
                             status_detail=EXCLUDED.status_detail,updated_at=now()""",
            (tenant_uid, job_id, job["source_type"], status, json.dumps(detail)),
        )
        cur.execute(
            """INSERT INTO audit_events
               (tenant_uid,job_id,actor,action,outcome,detail)
               VALUES (%s,%s,%s,%s,%s,%s)""",
            (tenant_uid, job_id, actor, f"job_state:{status}",
             "denied" if status == "blocked" else "error", json.dumps(detail)),
        )
        conn.commit()
        return {"event": event, "state": status}


def add_enrichment_observation(
    cfg: DbConfig,
    tenant_uid: str,
    job_id: uuid.UUID | str,
    provider: str,
    source: str,
    status: str,
    result: dict[str, Any] | None = None,
    indicator_id: int | None = None,
    observable_value: str | None = None,
    raw_artifact_id: uuid.UUID | str | None = None,
) -> dict[str, Any]:
    """Persist one normalized enrichment result and its scoped raw evidence."""
    require_tenant(tenant_uid)
    if not provider or not provider.strip() or not source or not source.strip():
        raise ValidationError("provider and source must be non-empty strings")
    if status not in {"ok", "not_found", "unavailable", "blocked", "error"}:
        raise ValidationError(f"invalid enrichment status: {status!r}")
    if indicator_id is None and (not observable_value or not observable_value.strip()):
        raise ValidationError("indicator_id or observable_value is required")
    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM jobs WHERE job_id = %s AND tenant_uid = %s",
            (job_id, tenant_uid),
        )
        if cur.fetchone() is None:
            raise CrossTenantAccessError(
                f"job {job_id} not found under tenant {tenant_uid}"
            )
        if indicator_id is not None:
            cur.execute(
                "SELECT 1 FROM indicators WHERE indicator_id = %s"
                " AND job_id = %s AND tenant_uid = %s",
                (indicator_id, job_id, tenant_uid),
            )
            if cur.fetchone() is None:
                raise CrossTenantAccessError(
                    f"indicator {indicator_id} is outside the job scope"
                )
        if raw_artifact_id is not None:
            cur.execute(
                "SELECT 1 FROM derived_artifacts WHERE derived_id = %s"
                " AND job_id = %s AND tenant_uid = %s",
                (raw_artifact_id, job_id, tenant_uid),
            )
            if cur.fetchone() is None:
                raise CrossTenantAccessError(
                    f"raw artifact {raw_artifact_id} is outside the job scope"
                )
        cur.execute(
            """
            INSERT INTO enrichment_observations (
                tenant_uid, job_id, provider, source, indicator_id,
                observable_value, result, status, raw_artifact_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING observation_id, tenant_uid, job_id, provider, source,
                      indicator_id, observable_value, result, status,
                      raw_artifact_id, observed_at, created_at
            """,
            (tenant_uid, job_id, provider.strip(), source.strip(), indicator_id,
             observable_value, json.dumps(result or {}), status, raw_artifact_id),
        )
        row = dict(cur.fetchone())
        conn.commit()
        return row


def add_risk_score(
    cfg: DbConfig,
    tenant_uid: str,
    job_id: uuid.UUID | str,
    classification: str,
    confidence: float,
    score: float,
    factors: dict[str, Any] | None = None,
    created_by: str = "engine",
) -> dict[str, Any]:
    """Persist a risk assessment; previous scores stay for history."""
    require_tenant(tenant_uid)
    if classification not in {"benign", "suspicious", "phishing", "malware_delivery",
                              "blocked_insufficient_evidence"}:
        raise ValidationError(f"invalid classification: {classification!r}")
    if not 0.0 <= confidence <= 1.0:
        raise ValidationError("confidence must be within [0, 1]")
    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM jobs WHERE job_id = %s AND tenant_uid = %s",
            (job_id, tenant_uid),
        )
        if cur.fetchone() is None:
            raise CrossTenantAccessError(
                f"job {job_id} not found under tenant {tenant_uid}"
            )
        cur.execute(
            """
            INSERT INTO risk_scores (tenant_uid, job_id, classification,
                                     confidence, score, factors, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING risk_score_id, classification, confidence, score, created_at
            """,
            (tenant_uid, job_id, classification, confidence, score,
             json.dumps(factors or {}), created_by),
        )
        row = dict(cur.fetchone())
        conn.commit()
        return row


def add_report(
    cfg: DbConfig,
    tenant_uid: str,
    job_id: uuid.UUID | str,
    submission_id: uuid.UUID | str,
    executive_finding: str,
    storage_pointer: str,
    generated_by: str,
    risk_score_id: int | None = None,
    audience: str = "internal",
    report_format: str = "markdown",
    evidence_manifest: dict[str, Any] | None = None,
    redaction_state: str = "redacted",
    data: bytes = b"",
) -> dict[str, Any]:
    """Persist a final report record linked to job + submission + risk score."""
    require_tenant(tenant_uid)
    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM jobs WHERE job_id = %s AND tenant_uid = %s"
            " AND submission_id = %s",
            (job_id, tenant_uid, submission_id),
        )
        if cur.fetchone() is None:
            raise CrossTenantAccessError(
                f"job {job_id} and submission {submission_id} are not linked"
            )
        if risk_score_id is not None:
            cur.execute(
                "SELECT 1 FROM risk_scores WHERE risk_score_id = %s"
                " AND job_id = %s AND tenant_uid = %s",
                (risk_score_id, job_id, tenant_uid),
            )
            if cur.fetchone() is None:
                raise CrossTenantAccessError(
                    f"risk score {risk_score_id} is outside the job scope"
                )
        # Next version per (tenant, job).
        cur.execute(
            "SELECT COALESCE(MAX(report_version), 0) + 1 AS v FROM reports"
            " WHERE tenant_uid = %s AND job_id = %s",
            (tenant_uid, job_id),
        )
        version = cur.fetchone()["v"]
        cur.execute(
            """
            INSERT INTO reports (
                tenant_uid, job_id, submission_id, report_version, audience,
                format, risk_score_id, executive_finding, evidence_manifest,
                redaction_state, storage_pointer, sha256, generated_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING report_id, report_version, audience, redaction_state, sha256
            """,
            (
                tenant_uid, job_id, submission_id, version, audience, report_format,
                risk_score_id, executive_finding, json.dumps(evidence_manifest or {}),
                redaction_state, storage_pointer, compute_sha256(data), generated_by,
            ),
        )
        row = dict(cur.fetchone())
        conn.commit()
        return row


def persist_report_bundle(
    cfg: DbConfig,
    *,
    tenant_uid: str,
    job_id: uuid.UUID | str,
    storage_writer: Callable[[str, bytes], str],
    actor: str = "report-generator",
) -> dict[str, Any]:
    """Generate and atomically link canonical JSON and Markdown report files.

    Artifact bytes are content-addressed before the database transaction commits.
    A failed SQL transaction can therefore leave only harmless unreferenced blobs,
    never a partial report lifecycle or partially linked evidence chain.
    """
    from .reports import REPORT_VERSION, assemble_content_pack, render_json, render_markdown

    tenant_uid = require_tenant(tenant_uid)
    bundle = get_job_bundle(cfg, tenant_uid, job_id)
    pack = assemble_content_pack(bundle)
    json_data = render_json(pack).encode("utf-8")
    markdown_data = render_markdown(pack).encode("utf-8")
    json_pointer = storage_writer(tenant_uid, json_data)
    markdown_pointer = storage_writer(tenant_uid, markdown_data)
    submission_id = bundle["job"]["submission_id"]
    risk_scores = bundle.get("risk_scores", [])
    risk_score_id = risk_scores[-1]["risk_score_id"] if risk_scores else None
    evidence = pack["observed_facts"]["submitted_evidence"] + pack["observed_facts"]["derived_artifacts"]
    manifest = {
        "schema": pack["schema"], "version": REPORT_VERSION,
        "content_pack_sha256": compute_sha256(json_data),
        "job": {"job_id": str(job_id), "submission_id": str(submission_id),
                "source_type": pack["job"]["source_type"],
                "state_at_assembly": pack["job"]["state"]},
        "evidence": [
            {key: row[key] for key in ("artifact_id", "relationship", "kind", "media_type",
                                       "sha256", "captured_at", "byte_size") if key in row}
            for row in evidence
        ],
    }
    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT submission_id, state FROM jobs WHERE job_id=%s AND tenant_uid=%s FOR UPDATE",
            (job_id, tenant_uid),
        )
        job = cur.fetchone()
        if job is None:
            raise CrossTenantAccessError(f"job {job_id} not found under tenant {tenant_uid}")
        if job["submission_id"] != submission_id:
            raise ValidationError("job changed during report generation")
        if job["state"] in {"blocked", "failed", "expired"}:
            raise ValidationError(f"cannot report a job in {job['state']} state")
        cur.execute(
            "UPDATE jobs SET state='reporting' WHERE job_id=%s AND tenant_uid=%s RETURNING state",
            (job_id, tenant_uid),
        )
        if cur.fetchone() is None:
            raise CrossTenantAccessError(f"job {job_id} not found under tenant {tenant_uid}")
        cur.execute(
            """INSERT INTO audit_events (tenant_uid,job_id,actor,action,outcome,detail)
               VALUES (%s,%s,%s,'job_state:reporting','ok',%s)""",
            (tenant_uid, job_id, actor,
             json.dumps({"reason": "report artifacts generated"})),
        )
        cur.execute("SELECT COALESCE(MAX(report_version),0)+1 AS v FROM reports WHERE tenant_uid=%s AND job_id=%s",
                    (tenant_uid, job_id))
        report_version = cur.fetchone()["v"]
        derived_rows = []
        for media_type, data, pointer in (
            ("application/json", json_data, json_pointer),
            ("text/markdown; charset=utf-8", markdown_data, markdown_pointer),
        ):
            cur.execute(
                """INSERT INTO derived_artifacts
                   (tenant_uid,job_id,submission_id,derived_kind,media_type,sha256,
                    byte_size,storage_pointer,produced_by,tool_version)
                   VALUES (%s,%s,%s,'report_file',%s,%s,%s,%s,%s,%s)
                   RETURNING derived_id,derived_kind,media_type,sha256,byte_size""",
                (tenant_uid, job_id, submission_id, media_type, compute_sha256(data),
                 len(data), pointer, actor, REPORT_VERSION),
            )
            derived_rows.append(dict(cur.fetchone()))
        manifest["report_files"] = [
            {"artifact_id": str(row["derived_id"]), "relationship": "generated_report",
             "kind": row["derived_kind"], "media_type": row["media_type"],
             "sha256": row["sha256"], "byte_size": row["byte_size"]}
            for row in derived_rows
        ]
        cur.execute(
            """INSERT INTO reports
               (tenant_uid,job_id,submission_id,report_version,audience,format,risk_score_id,
                executive_finding,evidence_manifest,redaction_state,storage_pointer,sha256,generated_by)
               VALUES (%s,%s,%s,%s,'internal','markdown',%s,%s,%s,'redacted',%s,%s,%s)
               RETURNING report_id,report_version,audience,format,redaction_state,sha256,evidence_manifest""",
            (tenant_uid, job_id, submission_id, report_version, risk_score_id,
             pack["executive_summary"]["finding"], json.dumps(manifest), markdown_pointer,
             compute_sha256(markdown_data), actor),
        )
        report = dict(cur.fetchone())
        cur.execute("UPDATE jobs SET state='completed',finished_at=now() WHERE job_id=%s AND tenant_uid=%s",
                    (job_id, tenant_uid))
        cur.execute(
            """INSERT INTO audit_events (tenant_uid,job_id,actor,action,outcome,detail)
               VALUES (%s,%s,%s,'job_state:completed','ok',%s)""",
            (tenant_uid, job_id, actor,
             json.dumps({"reason": "report bundle persisted"})),
        )
        conn.commit()
    return {"content_pack": pack, "json": json_data.decode("utf-8"),
            "markdown": markdown_data.decode("utf-8"), "report": report,
            "report_files": derived_rows, "state": "completed"}


def set_source_status(
    cfg: DbConfig,
    tenant_uid: str,
    job_id: uuid.UUID | str,
    source_type: str,
    status: str,
    status_detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Upsert per-source processing status for a job."""
    require_tenant(tenant_uid)
    if status not in {"received", "parsed", "scan_pending", "scanned", "enriched",
                      "unreachable", "blocked", "failed"}:
        raise ValidationError(f"invalid source status: {status!r}")
    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM jobs WHERE job_id = %s AND tenant_uid = %s",
            (job_id, tenant_uid),
        )
        if cur.fetchone() is None:
            raise CrossTenantAccessError(
                f"job {job_id} not found under tenant {tenant_uid}"
            )
        cur.execute(
            """
            INSERT INTO source_status (tenant_uid, job_id, source_type, status, status_detail)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (tenant_uid, job_id, source_type)
            DO UPDATE SET status = EXCLUDED.status,
                          status_detail = EXCLUDED.status_detail,
                          updated_at = now()
            RETURNING source_status_id, source_type, status, updated_at
            """,
            (tenant_uid, job_id, source_type, status, json.dumps(status_detail or {})),
        )
        row = dict(cur.fetchone())
        conn.commit()
        return row


# ---------------------------------------------------------------------------
# Tenant-scoped reads (the access layer every future API route must use)


def get_job_bundle(cfg: DbConfig, tenant_uid: str, job_id: uuid.UUID | str) -> dict[str, Any]:
    """Read one job with all scoped children, enforcing tenant scope on every table.

    This is the canonical read path: a wrong tenant never resolves the job
    (CrossTenantAccessError), proving records are not resolvable without the
    tenant key (threat model §4.1).
    """
    require_tenant(tenant_uid)
    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT j.job_id, j.tenant_uid, j.submission_id, j.source_type, j.state,
                   j.policy_decisions, j.created_at, j.finished_at,
                   s.case_reference, s.fidelity, s.submitted_at
            FROM jobs j
            JOIN submissions s ON s.submission_id = j.submission_id
                              AND s.tenant_uid = j.tenant_uid
            WHERE j.job_id = %s AND j.tenant_uid = %s
            """,
            (job_id, tenant_uid),
        )
        job = cur.fetchone()
        if job is None:
            raise CrossTenantAccessError(
                f"job {job_id} not found under tenant {tenant_uid}"
            )

        def scoped(query: str, key_column: str) -> list[dict[str, Any]]:
            cur.execute(query, (job_id, tenant_uid))
            return [dict(r) for r in cur.fetchall()]

        return {
            "job": dict(job),
            "input_artifacts": scoped(
                "SELECT artifact_id, artifact_type, media_type, sha256, byte_size,"
                " storage_pointer, is_sensitive, captured_at FROM input_artifacts"
                " WHERE job_id = %s AND tenant_uid = %s ORDER BY captured_at",
                "artifact_id",
            ),
            "derived_artifacts": scoped(
                "SELECT derived_id, derived_kind, media_type, sha256, byte_size, storage_pointer,"
                " produced_by, produced_at FROM derived_artifacts"
                " WHERE job_id = %s AND tenant_uid = %s ORDER BY produced_at",
                "derived_id",
            ),
            "indicators": scoped(
                "SELECT indicator_id, indicator_type, raw_value, defanged_value,"
                " provenance, corroboration_status, confidence FROM indicators"
                " WHERE job_id = %s AND tenant_uid = %s ORDER BY indicator_id",
                "indicator_id",
            ),
            "scan_events": scoped(
                "SELECT event_id, event_type, actor, route_label, outcome, detail,"
                " occurred_at FROM scan_events"
                " WHERE job_id = %s AND tenant_uid = %s ORDER BY occurred_at",
                "event_id",
            ),
            "enrichment_observations": scoped(
                "SELECT observation_id, provider, source, indicator_id,"
                " observable_value, result, status, raw_artifact_id, observed_at,"
                " created_at FROM enrichment_observations"
                " WHERE job_id = %s AND tenant_uid = %s ORDER BY observed_at",
                "observation_id",
            ),
            "risk_scores": scoped(
                "SELECT risk_score_id, classification, confidence, score, factors,"
                " created_at FROM risk_scores"
                " WHERE job_id = %s AND tenant_uid = %s ORDER BY created_at",
                "risk_score_id",
            ),
            "reports": scoped(
                "SELECT report_id, report_version, audience, format,"
                " executive_finding, redaction_state, sha256, generated_at FROM reports"
                " WHERE job_id = %s AND tenant_uid = %s ORDER BY report_version",
                "report_id",
            ),
            "source_status": scoped(
                "SELECT source_type, status, status_detail, updated_at FROM source_status"
                " WHERE job_id = %s AND tenant_uid = %s",
                "source_type",
            ),
        }


def list_tenant_jobs(cfg: DbConfig, tenant_uid: str, limit: int = 100) -> list[dict[str, Any]]:
    """List jobs for exactly one tenant; no cross-tenant query is expressible."""
    require_tenant(tenant_uid)
    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT j.job_id, j.source_type, j.state, j.created_at,
                   s.case_reference, s.fidelity
            FROM jobs j JOIN submissions s
              ON s.submission_id = j.submission_id AND s.tenant_uid = j.tenant_uid
            WHERE j.tenant_uid = %s
            ORDER BY j.created_at DESC
            LIMIT %s
            """,
            (tenant_uid, limit),
        )
        return [dict(r) for r in cur.fetchall()]
