"""Focused report artifact contract tests."""

from __future__ import annotations

import json
import uuid

# WHY: FastAPI's synchronous test client exercises routing and response encoding in-process.
from fastapi.testclient import TestClient

from pte.api import create_app
from pte.db import connect
from pte.reports import REPORT_SCHEMA, assemble_content_pack, render_json, render_markdown
from pte.services import (add_enrichment_observation, add_indicators, add_input_artifact,
                          add_risk_score, create_job, create_submission, get_job_bundle,
                          persist_report_bundle, set_source_status)


def _fedex_bundle() -> dict:
    job_id, submission_id = uuid.uuid4(), uuid.uuid4()
    return {
        "job": {"tenant_uid": "cust_FEDEX", "job_id": job_id,
                "submission_id": submission_id, "source_type": "ocr_text_message"},
        "input_artifacts": [
            {"artifact_id": uuid.uuid4(), "artifact_type": "ocr_text",
             "media_type": "text/plain", "sha256": "a" * 64},
            {"artifact_id": uuid.uuid4(), "artifact_type": "screenshot",
             "media_type": "image/png", "sha256": "b" * 64},
        ],
        "derived_artifacts": [{"derived_id": uuid.uuid4(), "derived_kind": "ocr_output",
                               "media_type": "text/plain", "sha256": "c" * 64}],
        "indicators": [{"indicator_type": "url",
                        "raw_value": "https://fedex.delivery.example.test/track?token=SECRET-PII",
                        "provenance": "ocr_derived", "corroboration_status": "unverified"}],
        "scan_events": [],
        "enrichment_observations": [{"source": "rdap_whois", "provider": "fixture",
                                     "status": "ok"}],
        "source_status": [{"source_type": "ocr_text_message", "status": "enriched"}],
        "risk_scores": [{"risk_score_id": 7, "classification": "phishing",
                         "confidence": 0.91, "score": 94.0, "factors": {}}],
        "reports": [],
    }


def _job(db, tenant_uid: str):
    submission = create_submission(db, tenant_uid, "ocr_text_message", fidelity="partial")
    job = create_job(db, tenant_uid, submission["submission_id"], "ocr_text_message")
    return submission, job


def test_fedex_content_pack_is_safe_complete_and_deterministic():
    bundle = _fedex_bundle()
    pack = assemble_content_pack(bundle)
    assert pack["schema"] == REPORT_SCHEMA
    assert pack["tenant_uid"] == "cust_FEDEX"
    assert pack["executive_summary"]["classification"] == "phishing"
    assert pack["observed_facts"]["screenshot_references"]
    ioc = pack["observed_facts"]["iocs"][0]
    assert ioc["value"] == "hxxps://fedex[.]delivery[.]example[.]test/[…redacted…]"
    assert ioc["provenance_label"].startswith("OCR-derived")
    assert pack["inferences"]["ttps"] and pack["defensive_recommendations"]
    rendered_json = render_json(pack)
    rendered_md = render_markdown(pack)
    assert rendered_json == render_json(assemble_content_pack(bundle))
    assert rendered_md == render_markdown(assemble_content_pack(bundle))
    forbidden = ("SECRET-PII", "token=", "storage_pointer", "/home/", "https://")
    assert not any(value in rendered_json + rendered_md for value in forbidden)


def test_missing_analysis_data_emits_explicit_caveats():
    bundle = _fedex_bundle()
    bundle.update({"risk_scores": [], "enrichment_observations": [], "source_status": [],
                   "scan_events": [], "input_artifacts": []})
    pack = assemble_content_pack(bundle)
    assert pack["executive_summary"]["classification"] == "blocked_insufficient_evidence"
    caveats = " ".join(pack["analyst_caveats"])
    assert "No risk score" in caveats and "No enrichment" in caveats and "No scanner" in caveats


def test_persist_report_bundle_links_files_manifest_hash_version_and_lifecycle(db, tenant_a):
    submission, job = _job(db, tenant_a)
    add_input_artifact(db, tenant_a, job["job_id"], submission["submission_id"],
                       "screenshot", "image/png", b"safe image bytes", "private/input.png")
    add_indicators(db, tenant_a, job["job_id"], [{
        "indicator_type": "url", "raw_value": "https://fedex.example.test/pay?otp=123456",
        "provenance": "ocr_derived"}])
    add_enrichment_observation(db, tenant_a, job["job_id"], "fixture", "rdap", "ok",
                               observable_value="fedex.example.test")
    set_source_status(db, tenant_a, job["job_id"], "ocr_text_message", "enriched")
    add_risk_score(db, tenant_a, job["job_id"], "phishing", .9, 93)
    written: dict[str, bytes] = {}

    def writer(tenant: str, data: bytes) -> str:
        pointer = f"opaque-{len(written)}"
        written[pointer] = data
        return pointer

    result = persist_report_bundle(db, tenant_uid=tenant_a, job_id=job["job_id"],
                                   storage_writer=writer)
    assert result["state"] == "completed" and len(result["report_files"]) == 2
    assert result["report"]["report_version"] == 1
    manifest = result["report"]["evidence_manifest"]
    assert manifest["version"] == "1.0" and len(manifest["report_files"]) == 2
    assert manifest["content_pack_sha256"] == result["report_files"][0]["sha256"]
    bundle = get_job_bundle(db, tenant_a, job["job_id"])
    assert bundle["job"]["state"] == "completed"
    assert sum(row["derived_kind"] == "report_file" for row in bundle["derived_artifacts"]) == 2
    with connect(db) as conn, conn.cursor() as cur:
        cur.execute("SELECT action FROM audit_events WHERE tenant_uid=%s AND job_id=%s ORDER BY audit_id",
                    (tenant_a, job["job_id"]))
        assert [row["action"] for row in cur.fetchall()][-2:] == ["job_state:reporting", "job_state:completed"]


def test_api_exports_and_cross_tenant_denial(db, tenant_a, tenant_b):
    submission, job = _job(db, tenant_a)
    add_risk_score(db, tenant_a, job["job_id"], "suspicious", .6, 65)

    class NoReadStore:
        def put(self, _tenant: str, _data: bytes) -> str:
            raise AssertionError("GET export must not read or write artifact bytes")

    client = TestClient(create_app(db, NoReadStore()))
    path = f"/v1/reports/{job['job_id']}"
    response = client.get(f"{path}/content-pack", params={"tenant_uid": tenant_a})
    assert response.status_code == 200
    assert response.json()["job_id"] == str(job["job_id"])
    assert "storage_pointer" not in json.dumps(response.json())
    markdown = client.get(f"{path}/markdown", params={"tenant_uid": tenant_a})
    assert markdown.status_code == 200 and "# Phishing Triage Analyst Report" in markdown.text
    assert client.get(f"{path}/content-pack", params={"tenant_uid": tenant_b}).status_code == 404
    assert client.get(f"{path}/content-pack").status_code == 422
