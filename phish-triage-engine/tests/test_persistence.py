"""Acceptance tests for task t_aeaf2caa.

Proves the three acceptance criteria from the card:
  1. tenant UID is required on every persisted record (schema + service level).
  2. job / artifact / report records are linked correctly end-to-end.
  3. cross-tenant access is structurally impossible via the service layer.
"""

from __future__ import annotations

import uuid

import psycopg
import pytest

from pte.db import connect
from pte.services import (
    CrossTenantAccessError,
    TenantRequiredError,
    ValidationError,
    add_derived_artifact,
    add_enrichment_observation,
    add_input_artifact,
    add_indicators,
    add_report,
    add_risk_score,
    add_scan_event,
    create_job,
    create_submission,
    get_job_bundle,
    list_tenant_jobs,
    set_job_state,
    set_source_status,
)


def _full_job(db, tenant_uid: str, source_type: str = "raw_url"):
    """Create a submission + queued job and return (submission, job)."""
    submission = create_submission(
        db, tenant_uid, source_type,
        submitted_by_type="customer_delegate",
        case_reference="CASE-1001",
        fidelity="full",
        envelope={"tenant_uid": tenant_uid, "source_type": source_type, "inputs": []},
    )
    job = create_job(db, tenant_uid, submission["submission_id"], source_type)
    return submission, job


# ---------------------------------------------------------------------------
# 1. Tenant UID is required


class TestTenantUidRequired:
    def test_service_rejects_missing_tenant(self, db):
        """Service layer refuses tenantless writes before touching Postgres."""
        with pytest.raises(TenantRequiredError):
            create_submission(db, "", "raw_url")
        with pytest.raises(TenantRequiredError):
            create_submission(db, None, "raw_url")
        with pytest.raises(TenantRequiredError):
            create_submission(db, "   ", "raw_url")
        with pytest.raises(CrossTenantAccessError):
            create_job(db, "cust_X", uuid.uuid4(), "raw_url")

    def test_schema_rejects_tenantless_row(self, db):
        """Defense in depth: the tenant trigger rejects NULL before the
        NOT NULL constraint is reached."""
        with connect(db) as conn, conn.cursor() as cur:
            with pytest.raises(psycopg.errors.RaiseException):
                cur.execute(
                    "INSERT INTO jobs (submission_id, source_type)"
                    " VALUES (gen_random_uuid(), 'raw_url')"
                )
            conn.rollback()

    def test_unknown_tenant_rejected(self, db):
        """A tenant UID that fails the FK check cannot create submissions."""
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            create_submission(db, "cust_DOES_NOT_EXIST", "raw_url")

    def test_tenant_trigger_blocks_empty_string(self, db):
        """The enforce_tenant_uid() trigger blocks blanking the tenant even on
        a direct UPDATE (defense in depth beyond the FK)."""
        with connect(db) as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO tenants (tenant_uid, display_name) VALUES ('cust_OK', 'OK')"
            )
            cur.execute(
                "INSERT INTO submissions (tenant_uid, source_type, submitted_by_type,"
                " consent_authorized, consent_no_credentials)"
                " VALUES ('cust_OK', 'raw_url', 'customer_delegate', TRUE, TRUE)"
            )
            with pytest.raises(psycopg.errors.RaiseException):
                cur.execute("UPDATE submissions SET tenant_uid = ''")
            conn.rollback()

    def test_audit_rejects_blank_and_unknown_tenant(self, db):
        """Audit rows are tenant-keyed even though business IDs stay unkeyed."""
        with connect(db) as conn, conn.cursor() as cur:
            with pytest.raises(psycopg.errors.RaiseException):
                cur.execute(
                    "INSERT INTO audit_events (tenant_uid, actor, action)"
                    " VALUES ('   ', 'test', 'blank')"
                )
            conn.rollback()
            with pytest.raises(psycopg.errors.RaiseException):
                cur.execute(
                    "INSERT INTO audit_events (tenant_uid, actor, action)"
                    " VALUES ('cust_UNKNOWN', 'test', 'unknown')"
                )
            conn.rollback()


# ---------------------------------------------------------------------------
# 2. Job / artifact / report linkage


class TestJobArtifactReportLinkage:
    def test_full_chain_end_to_end(self, db, tenant_a):
        """Submission -> job -> input artifact + derived artifact + indicators
        -> scan events -> risk score -> report, all linked and tenant-scoped."""
        submission, job = _full_job(db, tenant_a, "email_artifact")
        job_id = job["job_id"]
        sub_id = submission["submission_id"]

        artifact = add_input_artifact(
            db, tenant_a, job_id, sub_id, "eml", "message/rfc822",
            b"From: phish@example.invalid\r\nSubject: Urgent\r\n\r\nClick here",
            storage_pointer="artifacts/input/cust_TEST_TENANT_A/sample.eml",
            original_filename="sample.eml",
        )
        add_derived_artifact(
            db, tenant_a, job_id, sub_id, "parsed_headers", "application/json",
            b'{"From": ["phish@example.invalid"]}',
            storage_pointer="artifacts/derived/parsed_headers.json",
            produced_by="intake-parser", tool_version="0.1.0",
            parent_artifact_id=artifact["artifact_id"],
        )
        add_indicators(db, tenant_a, job_id, [
            {"indicator_type": "url", "raw_value": "http://evil.example.invalid/login",
             "defanged_value": "hxxp://evil.example.invalid/login"},
            {"indicator_type": "domain", "raw_value": "example.invalid",
             "provenance": "ocr_derived"},
        ])
        add_scan_event(db, tenant_a, job_id, "fetch_landing", "scanner-worker-01",
                       outcome="ok", route_label="pia-sidecar-required")
        observation = add_enrichment_observation(
            db, tenant_a, job_id, "rdap-provider", "rdap", "ok",
            result={"registrar": "Example Registrar"},
            observable_value="example.invalid",
            raw_artifact_id=add_derived_artifact(
                db, tenant_a, job_id, sub_id, "enrichment_payload",
                "application/json", b'{"registrar":"Example Registrar"}',
                "artifacts/derived/rdap.json", "enrichment-worker",
            )["derived_id"],
        )
        risk = add_risk_score(db, tenant_a, job_id, "phishing", 0.86, 92.5,
                              factors={"credential_form": True})
        report = add_report(
            db, tenant_a, job_id, sub_id,
            executive_finding="phishing: credential harvesting page",
            storage_pointer="reports/cust_TEST_TENANT_A/report-v1.md",
            generated_by="report-generator",
            risk_score_id=risk["risk_score_id"],
            data=b"# report",
        )
        set_job_state(db, tenant_a, job_id, "completed")

        bundle = get_job_bundle(db, tenant_a, job_id)
        assert bundle["job"]["state"] == "completed"
        assert bundle["job"]["submission_id"] == sub_id
        # Artifacts link to the job under the same tenant.
        assert len(bundle["input_artifacts"]) == 1
        assert bundle["input_artifacts"][0]["sha256"] == artifact["sha256"]
        assert len(bundle["derived_artifacts"]) == 2
        # Indicators and events are all present and scoped.
        assert {i["raw_value"] for i in bundle["indicators"]} == {
            "http://evil.example.invalid/login", "example.invalid"}
        assert any(i["provenance"] == "ocr_derived" for i in bundle["indicators"])
        assert bundle["scan_events"][0]["route_label"] == "pia-sidecar-required"
        assert bundle["enrichment_observations"][0]["observation_id"] == observation["observation_id"]
        assert bundle["enrichment_observations"][0]["result"]["registrar"] == "Example Registrar"
        # Risk score -> report FK resolves.
        assert bundle["reports"][0]["sha256"] == report["sha256"]
        assert bundle["risk_scores"][0]["risk_score_id"] == risk["risk_score_id"]
        assert bundle["reports"][0]["report_version"] == 1

    def test_report_versioning(self, db, tenant_a):
        """Second report for the same job becomes version 2, not an overwrite."""
        submission, job = _full_job(db, tenant_a)
        r1 = add_report(db, tenant_a, job["job_id"], submission["submission_id"],
                        "suspicious", "ptr1", "engine")
        r2 = add_report(db, tenant_a, job["job_id"], submission["submission_id"],
                        "phishing", "ptr2", "engine")
        assert (r1["report_version"], r2["report_version"]) == (1, 2)

    def test_report_cannot_link_foreign_risk_score(self, db, tenant_a):
        """A report cannot reference a risk_score_id that does not exist under
        the same tenant scope key (composite FK)."""
        submission_a, job_a = _full_job(db, tenant_a)
        with connect(db) as conn, conn.cursor() as cur:
            with pytest.raises(psycopg.errors.ForeignKeyViolation):
                cur.execute(
                    """
                    INSERT INTO reports (tenant_uid, job_id, submission_id,
                        executive_finding, storage_pointer, sha256, generated_by,
                        risk_score_id)
                    SELECT j.tenant_uid, j.job_id, j.submission_id, 'x', 'p',
                           repeat('a', 64), 't', 999999
                    FROM jobs j WHERE j.tenant_uid = %s LIMIT 1
                    """,
                    (tenant_a,),
                )
                cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
            conn.rollback()

    def test_report_cannot_link_risk_score_from_different_job(self, db, tenant_a):
        """Tenant equality alone is insufficient: risk score and report jobs match."""
        submission_a, job_a = _full_job(db, tenant_a)
        risk_a = add_risk_score(db, tenant_a, job_a["job_id"], "benign", 0.9, 1)
        submission_b, job_b = _full_job(db, tenant_a)
        with connect(db) as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO reports (tenant_uid, job_id, submission_id,
                    executive_finding, storage_pointer, sha256, generated_by,
                    risk_score_id)
                VALUES (%s, %s, %s, 'x', 'p', repeat('a', 64), 't', %s)
                """,
                (tenant_a, job_b["job_id"], submission_b["submission_id"],
                 risk_a["risk_score_id"]),
            )
            with pytest.raises(psycopg.errors.ForeignKeyViolation):
                cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
            conn.rollback()

    def test_artifact_immutability(self, db, tenant_a):
        """Original artifact hashes cannot be mutated (chain of custody)."""
        submission, job = _full_job(db, tenant_a)
        artifact = add_input_artifact(db, tenant_a, job["job_id"],
                                      submission["submission_id"], "eml",
                                      "message/rfc822", b"raw bytes", "ptr")
        with pytest.raises(psycopg.errors.RaiseException):
            with connect(db) as conn, conn.cursor() as cur:
                cur.execute(
                    "UPDATE input_artifacts SET sha256 = %s WHERE artifact_id = %s",
                    ("f" * 64, artifact["artifact_id"]),
                )

    def test_state_transition_logged_in_audit(self, db, tenant_a):
        """Lifecycle transitions record actor/reason as audit events (spec §6)."""
        submission, job = _full_job(db, tenant_a)
        set_job_state(db, tenant_a, job["job_id"], "scanning",
                      actor="scanner-worker-7", reason="disposable worker started")
        with connect(db) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT action, actor, detail FROM audit_events"
                " WHERE tenant_uid = %s AND job_id = %s",
                (tenant_a, job["job_id"]),
            )
            events = cur.fetchall()
        assert any(e["action"] == "job_state:scanning"
                   and e["actor"] == "scanner-worker-7"
                   and e["detail"]["reason"] == "disposable worker started"
                   for e in events)

    def test_audit_survives_business_row_deletion(self, db, tenant_a):
        submission, job = _full_job(db, tenant_a)
        set_job_state(db, tenant_a, job["job_id"], "failed", reason="cleanup")
        with connect(db) as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM jobs WHERE job_id = %s", (job["job_id"],))
            cur.execute(
                "DELETE FROM submissions WHERE submission_id = %s",
                (submission["submission_id"],),
            )
            cur.execute(
                "SELECT count(*) AS n FROM audit_events WHERE job_id = %s",
                (job["job_id"],),
            )
            assert cur.fetchone()["n"] == 1

    def test_audit_survives_tenant_deletion(self, db, tenant_a):
        submission, job = _full_job(db, tenant_a)
        set_job_state(db, tenant_a, job["job_id"], "failed", reason="tenant cleanup")
        with connect(db) as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM jobs WHERE job_id = %s", (job["job_id"],))
            cur.execute(
                "DELETE FROM submissions WHERE submission_id = %s",
                (submission["submission_id"],),
            )
            cur.execute("DELETE FROM tenants WHERE tenant_uid = %s", (tenant_a,))
            cur.execute(
                "SELECT tenant_uid, action FROM audit_events WHERE job_id = %s",
                (job["job_id"],),
            )
            event = cur.fetchone()
            assert event["tenant_uid"] == tenant_a
            assert event["action"] == "job_state:failed"

    def test_invalid_source_type_rejected(self, db, tenant_a):
        with pytest.raises(ValidationError):
            create_submission(db, tenant_a, "carrier_pigeon")

    def test_job_state_validation(self, db, tenant_a):
        """Only the twelve lifecycle states from the spec are accepted."""
        submission, job = _full_job(db, tenant_a)
        with pytest.raises(ValidationError):
            set_job_state(db, tenant_a, job["job_id"], "moonwalking")


# ---------------------------------------------------------------------------
# 3. Cross-tenant isolation


class TestCrossTenantIsolation:
    def test_job_not_resolvable_across_tenants(self, db, tenant_a, tenant_b):
        """A job created under tenant A cannot be read or transitioned by tenant B."""
        submission_a, job_a = _full_job(db, tenant_a)
        with pytest.raises(CrossTenantAccessError):
            get_job_bundle(db, tenant_b, job_a["job_id"])
        with pytest.raises(CrossTenantAccessError):
            set_job_state(db, tenant_b, job_a["job_id"], "completed")

    def test_cannot_attach_artifact_across_tenants(self, db, tenant_a, tenant_b):
        """Tenant B cannot attach evidence to tenant A's job."""
        submission_a, job_a = _full_job(db, tenant_a)
        with pytest.raises((CrossTenantAccessError, psycopg.errors.ForeignKeyViolation)):
            add_input_artifact(db, tenant_b, job_a["job_id"],
                               submission_a["submission_id"], "eml",
                               "message/rfc822", b"sneaky", "ptr")

    def test_cannot_create_job_from_foreign_submission(self, db, tenant_a, tenant_b):
        """Tenant B cannot create a job from tenant A's submission."""
        submission_a, _ = _full_job(db, tenant_a)
        with pytest.raises(CrossTenantAccessError):
            create_job(db, tenant_b, submission_a["submission_id"], "raw_url")

    def test_listing_is_tenant_scoped(self, db, tenant_a, tenant_b):
        _full_job(db, tenant_a)
        _full_job(db, tenant_b)
        jobs_a = list_tenant_jobs(db, tenant_a)
        jobs_b = list_tenant_jobs(db, tenant_b)
        assert len(jobs_a) == 1 and len(jobs_b) == 1
        assert jobs_a[0]["job_id"] != jobs_b[0]["job_id"]

    def test_sql_level_composite_fk_blocks_cross_tenant_child(self, db, tenant_a, tenant_b):
        """Even raw SQL cannot attach a scan event to another tenant's job:
        the (job_id, tenant_uid) composite FK fails because the same job_id
        does not exist under tenant B's key."""
        _, job_a = _full_job(db, tenant_a)
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            with connect(db) as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO scan_events (tenant_uid, job_id, event_type, actor,"
                    " outcome) VALUES (%s, %s, 'probe', 'attacker', 'ok')",
                    (tenant_b, job_a["job_id"]),
                )

    def test_sql_job_cannot_pair_submission_with_other_tenant(
        self, db, tenant_a, tenant_b
    ):
        submission_a = create_submission(db, tenant_a, "raw_url")
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            with connect(db) as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO jobs (tenant_uid, submission_id, source_type)"
                    " VALUES (%s, %s, 'raw_url')",
                    (tenant_b, submission_a["submission_id"]),
                )

    def test_sql_child_cannot_mix_job_and_submission(self, db, tenant_a):
        submission_a, job_a = _full_job(db, tenant_a)
        submission_b, _ = _full_job(db, tenant_a)
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            with connect(db) as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO input_artifacts (
                        tenant_uid, job_id, submission_id, artifact_type,
                        media_type, sha256, byte_size, storage_pointer
                    ) VALUES (%s, %s, %s, 'eml', 'message/rfc822',
                              repeat('a', 64), 1, 'ptr')
                    """,
                    (tenant_a, job_a["job_id"], submission_b["submission_id"]),
                )

    def test_derived_parent_fk_includes_submission_scope(self, db, tenant_a):
        submission, job = _full_job(db, tenant_a)
        artifact = add_input_artifact(
            db, tenant_a, job["job_id"], submission["submission_id"], "eml",
            "message/rfc822", b"parent", "parent-ptr",
        )
        with connect(db) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT pg_get_constraintdef(oid) AS definition"
                " FROM pg_constraint"
                " WHERE conrelid = 'derived_artifacts'::regclass"
                " AND contype = 'f' AND conkey[1] = ("
                "   SELECT attnum FROM pg_attribute"
                "   WHERE attrelid = 'derived_artifacts'::regclass"
                "   AND attname = 'parent_artifact_id'"
                " )"
            )
            definition = cur.fetchone()["definition"]
        assert "parent_artifact_id, job_id, submission_id, tenant_uid" in definition

    @pytest.mark.parametrize("writer", ["scan_event", "risk_score", "source_status"])
    def test_service_child_writes_validate_job_scope(
        self, db, tenant_a, tenant_b, writer
    ):
        _, job = _full_job(db, tenant_a)
        with pytest.raises(CrossTenantAccessError):
            if writer == "scan_event":
                add_scan_event(db, tenant_b, job["job_id"], "probe", "test")
            elif writer == "risk_score":
                add_risk_score(db, tenant_b, job["job_id"], "benign", 1.0, 0.0)
            else:
                set_source_status(db, tenant_b, job["job_id"], "raw_url", "received")
