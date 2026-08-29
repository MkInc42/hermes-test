"""Focused acceptance tests for the tenant-scoped intake API."""

from __future__ import annotations

from pathlib import Path
import hashlib

from fastapi.testclient import TestClient
import pytest

from pte.api import create_app
from pte.artifacts import ArtifactStore
from pte.db import connect


@pytest.fixture()
def client(db, tenant_a, tmp_path: Path):
    with TestClient(create_app(db, ArtifactStore(tmp_path / "artifacts"))) as test_client:
        yield test_client


def attested(tenant_uid: str) -> dict:
    return {"tenant_uid": tenant_uid, "authorization_attested": True,
            "no_credentials_acknowledged": True}


def test_valid_url_normalizes_and_queues(client, db, tenant_a):
    response = client.post("/v1/intake/url", json={**attested(tenant_a),
                                                    "url": "  HTTPS://BÜCHER.Example/Pay  "})
    assert response.status_code == 202
    result = response.json()
    normalized = "https://xn--bcher-kva.example/Pay"
    assert "normalized_url" not in result["policy"]
    assert result["policy"]["normalization"] == {
        "applied": True, "sha256": hashlib.sha256(normalized.encode()).hexdigest()}
    assert normalized not in response.text
    assert "BÜCHER" not in response.text
    assert result["state"] == "queued"
    assert "Pay" not in str(result["artifacts"])
    with connect(db) as conn, conn.cursor() as cur:
        cur.execute("SELECT state, policy_decisions FROM jobs WHERE tenant_uid=%s AND job_id=%s",
                    (tenant_a, result["job_id"]))
        job = cur.fetchone()
        assert job["state"] == "queued"
        assert job["policy_decisions"]["normalized_url"] == normalized
        cur.execute("SELECT raw_value FROM indicators WHERE tenant_uid=%s AND job_id=%s",
                    (tenant_a, result["job_id"]))
        assert cur.fetchone()["raw_value"] == normalized


@pytest.mark.parametrize("url", ["file:///etc/passwd", "javascript:alert(1)",
                                  "data:text/html,x", "ftp://example.com/x",
                                  "mailto:a@example.com", "chrome://settings"])
def test_dangerous_schemes_rejected(client, tenant_a, url):
    assert client.post("/v1/intake/url", json={**attested(tenant_a), "url": url}).status_code == 422


def test_userinfo_deception_rejected(client, tenant_a):
    response = client.post("/v1/intake/url", json={**attested(tenant_a),
                                                    "url": "https://fedex.com@evil.example/login"})
    assert response.status_code == 422


def test_email_paste_and_forwarded_fidelity(client, db, tenant_a):
    canonical = b"From: sender@example.test\r\n\r\nhello"
    full = client.post("/v1/intake/email/paste", json={**attested(tenant_a),
        "mode": "headers_body", "raw_headers": "From: sender@example.test", "body": "hello"})
    assert full.status_code == 202
    full_result = full.json()
    assert full_result["fidelity"] == "full"
    assert "sender@example.test" not in full.text
    assert "hello" not in full.text
    derived = full_result["derived_artifacts"][0]
    assert derived["derived_kind"] == "parsed_headers"
    assert len(derived["sha256"]) == 64
    assert derived["parent_artifact_id"] == full_result["artifacts"][0]["artifact_id"]
    with connect(db) as conn, conn.cursor() as cur:
        cur.execute("SELECT parent_artifact_id FROM derived_artifacts WHERE derived_id=%s",
                    (derived["derived_id"],))
        assert str(cur.fetchone()["parent_artifact_id"]) == full_result["artifacts"][0]["artifact_id"]
        cur.execute("SELECT storage_pointer FROM input_artifacts WHERE artifact_id=%s",
                    (full_result["artifacts"][0]["artifact_id"],))
        pointer = cur.fetchone()["storage_pointer"]
    assert (client.app.state.artifact_store.root / pointer).read_bytes() == canonical
    forwarded = client.post("/v1/intake/email/paste", json={**attested(tenant_a),
        "mode": "forwarded_body", "body": "Forwarded message without headers"})
    assert forwarded.status_code == 202
    assert forwarded.json()["fidelity"] == "low"
    assert forwarded.json()["policy"]["full_headers"] is False


def test_eml_upload_preserved_and_parsed(client, db, tenant_a):
    eml = b"From: sender@example.test\r\nSubject: Test\r\n\r\nExact body\r\n"
    response = client.post("/v1/intake/email/upload", data=attested(tenant_a),
                           files={"file": ("sample.eml", eml, "message/rfc822")})
    assert response.status_code == 202
    artifact = response.json()["artifacts"][0]
    assert artifact["byte_size"] == len(eml)
    assert len(artifact["sha256"]) == 64
    derived = response.json()["derived_artifacts"][0]
    assert derived["parent_artifact_id"] == artifact["artifact_id"]
    with connect(db) as conn, conn.cursor() as cur:
        cur.execute("SELECT storage_pointer FROM input_artifacts WHERE artifact_id=%s",
                    (artifact["artifact_id"],))
        pointer = cur.fetchone()["storage_pointer"]
    assert (client.app.state.artifact_store.root / pointer).read_bytes() == eml


def test_msg_upload_is_preservation_only(client, db, tenant_a):
    msg = b"\xd0\xcf\x11\xe0exact-msg-bytes\x00\xff"
    response = client.post("/v1/intake/email/upload", data=attested(tenant_a),
                           files={"file": ("sample.msg", msg, "application/vnd.ms-outlook")})
    assert response.status_code == 202
    result = response.json()
    assert result["derived_artifacts"] == []
    with connect(db) as conn, conn.cursor() as cur:
        cur.execute("SELECT storage_pointer FROM input_artifacts WHERE artifact_id=%s",
                    (result["artifacts"][0]["artifact_id"],))
        pointer = cur.fetchone()["storage_pointer"]
    assert (client.app.state.artifact_store.root / pointer).read_bytes() == msg


def test_bad_email_type_and_oversize_rejected(client, tenant_a):
    bad = client.post("/v1/intake/email/upload", data=attested(tenant_a),
                      files={"file": ("mail.exe", b"MZ", "application/octet-stream")})
    assert bad.status_code == 422
    huge = client.post("/v1/intake/email/upload", data=attested(tenant_a),
                       files={"file": ("mail.eml", b"x" * (10 * 1024 * 1024 + 1),
                                       "message/rfc822")})
    assert huge.status_code == 413


def test_multipart_attestation_validation_is_redacted(client):
    invalid_tenant = "private-tenant-value-" + "x" * 256
    response = client.post("/v1/intake/email/upload", data=attested(invalid_tenant),
                           files={"file": ("sample.eml", b"From: sender@example.test\r\n\r\nbody",
                                           "message/rfc822")})
    assert response.status_code == 422
    assert response.json() == {"detail": "request validation failed"}
    assert invalid_tenant not in response.text


def test_ocr_preserves_context_and_labels_indicators(client, db, tenant_a):
    text = "Delivery alert\nVisit https://EXAMPLE.com/pay\nCall +1 (212) 555-0199"
    response = client.post("/v1/intake/ocr", json={**attested(tenant_a), "ocr_text": text,
                                                   "platform": "sms", "confidence": 0.8})
    assert response.status_code == 202
    assert text not in response.text
    assert "EXAMPLE.com/pay" not in response.text
    with connect(db) as conn, conn.cursor() as cur:
        cur.execute("SELECT indicator_type, provenance FROM indicators WHERE job_id=%s",
                    (response.json()["job_id"],))
        rows = cur.fetchall()
    assert {row["indicator_type"] for row in rows} >= {"url", "domain", "phone_number"}
    assert all(row["provenance"] == "ocr_derived" for row in rows)


def test_schema_validation_error_does_not_echo_content(client, tenant_a):
    secret = "private OCR https://credential.example/reset?token=secret"
    response = client.post("/v1/intake/ocr", json={**attested(tenant_a),
                                                   "ocr_text": secret, "confidence": 2})
    assert response.status_code == 422
    assert response.json() == {"detail": "request validation failed"}
    assert secret not in response.text


def test_storage_error_is_safe(client, tenant_a, monkeypatch):
    def fail_storage(_tenant_uid, _data):
        raise OSError("/secret/path containing submitted-content")

    monkeypatch.setattr(client.app.state.artifact_store, "put", fail_storage)
    response = client.post("/v1/intake/url", json={**attested(tenant_a),
                                                   "url": "https://secret.example/path"})
    assert response.status_code == 503
    assert response.json() == {"detail": "artifact storage unavailable"}
    assert "secret" not in response.text


def test_screenshot_type_signature_and_size_boundaries(client, tenant_a):
    png = b"\x89PNG\r\n\x1a\n" + b"safe"
    valid = client.post("/v1/intake/screenshot", data=attested(tenant_a),
                        files={"file": ("capture.png", png, "image/png")})
    assert valid.status_code == 202
    mismatch = client.post("/v1/intake/screenshot", data=attested(tenant_a),
                           files={"file": ("capture.png", b"not png", "image/png")})
    assert mismatch.status_code == 422
    huge = client.post("/v1/intake/screenshot", data=attested(tenant_a),
                       files={"file": ("capture.png", b"\x89PNG\r\n\x1a\n" +
                                       b"x" * (15 * 1024 * 1024), "image/png")})
    assert huge.status_code == 413


def test_screenshot_ocr_is_derived_and_redacted(client, db, tenant_a):
    png = b"\x89PNG\r\n\x1a\n" + b"safe"
    ocr_text = "Private alert: visit https://ocr.example/reset"
    response = client.post("/v1/intake/screenshot",
                           data={**attested(tenant_a), "ocr_text": ocr_text},
                           files={"file": ("capture.png", png, "image/png")})

    assert response.status_code == 202
    result = response.json()
    assert ocr_text not in response.text
    assert "ocr.example" not in response.text
    assert len(result["artifacts"]) == 1
    assert len(result["derived_artifacts"]) == 1
    derived = result["derived_artifacts"][0]
    assert derived["derived_kind"] == "ocr_output"
    assert derived["parent_artifact_id"] == result["artifacts"][0]["artifact_id"]

    with connect(db) as conn, conn.cursor() as cur:
        cur.execute("SELECT artifact_type FROM input_artifacts WHERE job_id=%s",
                    (result["job_id"],))
        assert [row["artifact_type"] for row in cur.fetchall()] == ["screenshot"]
        cur.execute("SELECT parent_artifact_id, derived_kind FROM derived_artifacts WHERE job_id=%s",
                    (result["job_id"],))
        stored = cur.fetchone()
        assert str(stored["parent_artifact_id"]) == result["artifacts"][0]["artifact_id"]
        assert stored["derived_kind"] == "ocr_output"
        cur.execute("SELECT provenance FROM indicators WHERE job_id=%s", (result["job_id"],))
        assert {row["provenance"] for row in cur.fetchall()} == {"ocr_derived"}


def test_missing_consent_and_unknown_tenant_do_not_persist(client, db, tenant_a):
    denied = client.post("/v1/intake/url", json={**attested(tenant_a),
        "authorization_attested": False, "url": "https://example.test"})
    assert denied.status_code == 400
    unknown = client.post("/v1/intake/url", json={**attested("cust_UNKNOWN"),
                                                   "url": "https://example.test"})
    assert unknown.status_code == 404
    with connect(db) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM submissions")
        assert cur.fetchone()["n"] == 0


def test_tenant_scoping(client, db, tenant_a, tenant_b):
    response = client.post("/v1/intake/url", json={**attested(tenant_a),
                                                   "url": "https://example.test"})
    assert response.status_code == 202
    with connect(db) as conn, conn.cursor() as cur:
        cur.execute("SELECT tenant_uid FROM jobs WHERE job_id=%s", (response.json()["job_id"],))
        assert cur.fetchone()["tenant_uid"] == tenant_a
        cur.execute("SELECT count(*) AS n FROM jobs WHERE tenant_uid=%s", (tenant_b,))
        assert cur.fetchone()["n"] == 0
