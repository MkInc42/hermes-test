"""Focused report artifact contract tests."""

from __future__ import annotations

import json
import uuid

# WHY: FastAPI's synchronous test client exercises routing and response encoding in-process.
from fastapi.testclient import TestClient

from pte.api import create_app
from pte.db import connect
from pte.enrichment import SOURCE_NAMES
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


def test_adversarial_indicator_values_fail_closed_without_leaking_secrets():
    bundle = _fedex_bundle()
    attacks = [
        ("domain", "safe.example **DOMAIN-SECRET**"),
        ("hostname", "host.example`HOST-SECRET`"),
        ("ip", "999.999.999.999 IP-SECRET"),
        ("email_address", "victim EMAIL-SECRET@example.test"),
        ("file_hash", "not-hex-HASH-SECRET"),
        ("url", "https://URL-SECRET:password@fedex.example.test/private?token=QUERY-SECRET"),
        ("domain", "fedex.example.test\nCONTROL-SECRET"),
    ]
    bundle["indicators"].extend({
        "indicator_type": indicator_type,
        "raw_value": raw_value,
        "provenance": "submitted",
        "corroboration_status": "unverified",
    } for indicator_type, raw_value in attacks)

    pack = assemble_content_pack(bundle)
    rendered_json = render_json(pack)
    rendered_md = render_markdown(pack)
    combined = rendered_json + rendered_md

    values = {ioc["value"] for ioc in pack["observed_facts"]["iocs"]}
    assert "hxxps://fedex[.]delivery[.]example[.]test/[…redacted…]" in values
    assert sum(ioc["value"] == "[redacted indicator]"
               for ioc in pack["observed_facts"]["iocs"]) == len(attacks) - 1
    url_ioc = next(ioc for ioc in pack["observed_facts"]["iocs"]
                   if ioc["type"] == "url" and ioc["value"].startswith("hxxps://fedex[.]example"))
    assert url_ioc["value"] == "hxxps://fedex[.]example[.]test/[…redacted…]"
    for secret in ("DOMAIN-SECRET", "HOST-SECRET", "IP-SECRET", "EMAIL-SECRET",
                   "HASH-SECRET", "URL-SECRET", "password", "QUERY-SECRET",
                   "CONTROL-SECRET"):
        assert secret not in combined


def test_missing_analysis_data_emits_explicit_caveats():
    bundle = _fedex_bundle()
    bundle.update({"risk_scores": [], "enrichment_observations": [], "source_status": [],
                   "scan_events": [], "input_artifacts": []})
    pack = assemble_content_pack(bundle)
    assert pack["executive_summary"]["classification"] == "blocked_insufficient_evidence"
    caveats = " ".join(pack["analyst_caveats"])
    assert "No risk score" in caveats and "No enrichment" in caveats and "No scanner" in caveats


def test_untrusted_report_text_is_omitted_or_replaced_in_json_and_markdown():
    bundle = _fedex_bundle()
    bundle["job"]["case_reference"] = "https://secret.example/reset?token=TOPSECRET"
    attacks = [
        "https://secret.example/path?token=TOPSECRET",
        "Bearer SUPERSECRET", "api_token=TOPSECRET123", "user@example.test",
        "/home/analyst/private.txt", "s3://private-bucket/customer/object",
        "`code` **bold** [link](https://secret.example)",
    ]
    bundle["enrichment_observations"] = [{
        "source": attack, "provider": attack, "status": attack,
        "result": {"message": attack},
    } for attack in attacks]
    bundle["source_status"] = [{
        "source_type": attack, "status": attack, "status_detail": {"message": attack},
    } for attack in attacks]

    pack = assemble_content_pack(bundle)
    rendered_json = render_json(pack)
    rendered_md = render_markdown(pack)
    combined = rendered_json + rendered_md

    assert "case_reference" not in pack["submission"]
    for attack in attacks:
        assert attack not in combined
    for secret in ("TOPSECRET", "SUPERSECRET", "user@example.test", "/home/",
                   "s3://", "`code`", "**bold**", "[link]"):
        assert secret not in combined
    sources = pack["observed_facts"]["source_status"]
    assert all(source["source"] == "unknown" and source["status"] == "unknown"
               and "limitation" not in source for source in sources)
    assert {source["provider"] for source in sources} == {"unknown", "internal pipeline"}


def test_known_enrichment_sources_and_safe_provider_identifiers_remain_visible():
    bundle = _fedex_bundle()
    bundle["enrichment_observations"] = [
        {"source": source, "provider": "rdap-provider" if source == "rdap_whois"
         else f"{source}-fixture", "status": "ok", "result": {"message": "omitted"}}
        for source in SOURCE_NAMES
    ] + [{
        "source": "dns", "provider": "api_token-TOPSECRET", "status": "ok",
        "result": {"message": "https://secret.example/private"},
    }]
    bundle["source_status"] = [
        {"source_type": source, "status": "received", "status_detail": {"message": "omitted"}}
        for source in ("raw_url", "email_artifact", "ocr_text_message", "screenshot_evidence")
    ]

    pack = assemble_content_pack(bundle)
    sources = pack["observed_facts"]["source_status"]
    rendered = render_json(pack) + render_markdown(pack)

    assert set(SOURCE_NAMES).issubset({item["source"] for item in sources})
    assert {"raw_url", "email_artifact", "ocr_text_message", "screenshot_evidence"}.issubset(
        {item["source"] for item in sources}
    )
    expected_providers = {
        "rdap-provider" if source == "rdap_whois" else f"{source}-fixture"
        for source in SOURCE_NAMES
    }
    assert expected_providers.issubset({item["provider"] for item in sources})
    assert any(item["provider"] == "unknown" for item in sources)
    assert "TOPSECRET" not in rendered
    assert "secret.example" not in rendered
    assert all("limitation" not in item for item in sources)


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
