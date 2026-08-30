"""Acceptance tests for deterministic OSINT enrichment and risk scoring."""

from __future__ import annotations

import json
import socket
import threading
import time

import psycopg

import pte.enrichment_worker as enrichment_worker
from pte.artifacts import ArtifactStore
from pte.adapters import dns_lookup, unavailable_provider_results
from pte.enrichment import (
    SOURCE_NAMES,
    analyze_dom,
    analyze_url,
    build_enrichment_contract,
    canonical_json,
    persist_enrichment_job,
)
from pte.enrichment_worker import run_one_shot
from pte.services import add_indicators, create_job, create_submission, get_job_bundle


FIXTURE = json.loads((__import__("pathlib").Path(__file__).parent / "fixtures" / "fedex_smishing_case.json").read_text())


def _fedex_contract():
    return build_enrichment_contract(
        target_url=FIXTURE["target_url"],
        source_type=FIXTURE["source_type"],
        provider_results=FIXTURE["provider_results"],
        dom_html=FIXTURE["dom_html"],
        brand_terms=FIXTURE["brand_terms"],
    )


def test_url_parsing_tricks_explain_brand_impersonation_without_network_io():
    parsed = analyze_url(FIXTURE["target_url"], brand_terms=FIXTURE["brand_terms"])

    assert parsed["host"] == "fedex.delivery.example.test"
    assert parsed["registered_domain"] == "example.test"
    assert parsed["subdomain"] == "fedex.delivery"
    assert parsed["query_keys"] == ["pkg"]
    assert parsed["tricks"] == [{
        "name": "brand_in_subdomain",
        "severity": "high",
        "evidence": "'fedex' appears outside the registrable domain",
    }]


def test_url_parsing_uses_pinned_public_suffix_rules_for_multi_label_suffixes():
    parsed = analyze_url("https://www.fedex.co.uk/track", brand_terms=["fedex"])

    assert parsed["host"] == "www.fedex.co.uk"
    assert parsed["registered_domain"] == "fedex.co.uk"
    assert parsed["subdomain"] == "www"
    assert parsed["tricks"] == []


def test_url_parsing_uses_complete_offline_psl_for_common_omitted_suffixes():
    co_za = analyze_url("https://www.fedex.co.za/track", brand_terms=["fedex"])
    com_ar = analyze_url("https://www.fedex.com.ar/track", brand_terms=["fedex"])

    assert co_za["registered_domain"] == "fedex.co.za"
    assert co_za["tricks"] == []
    assert com_ar["registered_domain"] == "fedex.com.ar"
    assert com_ar["tricks"] == []


def test_url_parsing_honors_psl_wildcard_and_exception_rules():
    wildcard = analyze_url("https://fedex.account.ck/track", brand_terms=["fedex"])
    exception = analyze_url("https://account.www.ck/track")

    assert wildcard["registered_domain"] == "fedex.account.ck"
    assert wildcard["subdomain"] == ""
    assert wildcard["tricks"] == []
    assert exception["registered_domain"] == "www.ck"
    assert exception["subdomain"] == "account"


def test_url_parsing_still_flags_brand_abuse_above_registrable_domain():
    parsed = analyze_url("https://fedex.delivery.co.uk/track", brand_terms=["fedex"])

    assert parsed["registered_domain"] == "delivery.co.uk"
    assert parsed["subdomain"] == "fedex"
    assert parsed["tricks"] == [{
        "name": "brand_in_subdomain",
        "severity": "high",
        "evidence": "'fedex' appears outside the registrable domain",
    }]


def test_dom_indicators_extract_credential_card_and_otp_fields_statically():
    dom = analyze_dom(FIXTURE["dom_html"])

    assert dom["available"] is True
    assert [field["id"] for field in dom["credential_fields"]] == ["email", "password"]
    assert [field["id"] for field in dom["card_fields"]] == ["cardNumber", "cvv"]
    assert [field["id"] for field in dom["otp_fields"]] == ["otp"]
    assert dom["forms"] == [{"action": "/submit", "method": "post"}]
    assert dom["support_or_verification_buttons"] == ["Verify and Continue"]
    assert "JavaScript event handlers were not executed" in dom["limitations"][0]


def test_dom_indicators_normalize_common_identifier_styles_without_autocomplete():
    dom = analyze_dom("""
        <form>
          <input id="cardNumber">
          <input name="card_number">
          <input id="card-number">
          <input name="otpCode">
          <input id="otp_code">
          <input name="one-time-code">
        </form>
    """)

    assert [field["id"] or field["name"] for field in dom["card_fields"]] == [
        "cardNumber",
        "card_number",
        "card-number",
    ]
    assert [field["id"] or field["name"] for field in dom["otp_fields"]] == [
        "otpCode",
        "otp_code",
        "one-time-code",
    ]


def test_fedex_enrichment_contract_has_every_source_status_and_is_canonical():
    contract = _fedex_contract()
    reparsed = json.loads(canonical_json(contract))

    assert reparsed == contract
    assert contract["schema_version"] == 1
    assert contract["worker"] == "enrichment-worker"
    assert [item["source"] for item in contract["sources"]] == sorted(SOURCE_NAMES)
    assert {item["source"]: item["status"] for item in contract["sources"]} == {
        "asn_hosting": "ok",
        "dns": "ok",
        "domain_age": "ok",
        "dom_indicators": "ok",
        "google_safe_browsing": "not_found",
        "otx": "ok",
        "rdap_whois": "ok",
        "source_status": "ok",
        "tls_certificate_transparency": "ok",
        "url_parsing_tricks": "ok",
        "urlhaus_abusech": "not_found",
    }
    assert contract["target"] == {
        "url": FIXTURE["target_url"],
        "host": "fedex.delivery.example.test",
        "registered_domain": "example.test",
        "source_type": "ocr_text_message",
    }


def test_fedex_risk_score_is_evidence_based_not_black_box():
    risk = _fedex_contract()["risk"]
    descriptions = {item["description"] for item in risk["evidence"]}

    assert risk["classification"] == "phishing"
    assert risk["score"] == 100.0
    assert 0.5 <= risk["confidence"] <= 0.95
    assert risk["method"] == "deterministic-weighted-evidence-v1"
    assert "DOM contains credential/login fields" in descriptions
    assert "DOM requests payment-card data" in descriptions
    assert "DOM requests OTP/MFA/security-code data" in descriptions
    assert "Domain age is 1 days" in descriptions
    assert any("Reputation coverage incomplete" in item for item in risk["limitations"])
    assert all("verdict" not in item for item in risk["evidence"])


def test_missing_provider_and_dom_results_are_limited_not_silent():
    contract = build_enrichment_contract(
        target_url="https://example.test/",
        source_type="raw_url",
        provider_results={},
        dom_html=None,
    )
    statuses = {item["source"]: item["status"] for item in contract["sources"]}

    assert statuses["dns"] == "unavailable"
    assert statuses["dom_indicators"] == "unavailable"
    assert contract["risk"]["classification"] == "blocked_insufficient_evidence"
    assert "DOM artifact was unavailable" in " ".join(contract["risk"]["limitations"])
    assert "No provider result was supplied" in " ".join(contract["risk"]["limitations"])


def test_safe_local_defaults_cover_every_tool_backed_source_slot():
    results = unavailable_provider_results("example.test")

    assert set(results) == {
        "urlhaus_abusech", "otx", "google_safe_browsing", "dns",
        "rdap_whois", "domain_age", "asn_hosting", "tls_certificate_transparency",
    }
    assert {item["status"] for item in results.values()} == {"unavailable"}
    assert all(item["limitations"] for item in results.values())


def test_dns_adapter_normalizes_addresses_without_connecting_to_services():
    def resolver(_hostname):
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.5", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.5", 0)),
        ]

    result = dns_lookup("example.test", resolver=resolver)

    assert result["status"] == "ok"
    assert result["data"]["addresses"] == ["192.0.2.5", "2001:db8::1"]
    assert "no service connection" in result["limitations"][0]


def test_dns_adapter_returns_deterministic_not_found_unavailable_and_error():
    def missing(_hostname):
        raise socket.gaierror(socket.EAI_NONAME, "not found")

    def slow(_hostname):
        time.sleep(0.05)
        return []

    def broken(_hostname):
        raise OSError("resolver unavailable")

    assert dns_lookup("missing.test", resolver=missing)["status"] == "not_found"
    timed_out = dns_lookup("slow.test", timeout_seconds=0.001, resolver=slow)
    assert timed_out["status"] == "unavailable"
    assert "0.001s deadline" in timed_out["limitations"][0]
    assert dns_lookup("broken.test", resolver=broken)["status"] == "error"


def test_dns_adapter_deadline_does_not_leave_a_nondaemon_worker():
    release = threading.Event()

    def stalled(_hostname):
        release.wait()
        return []

    started = time.monotonic()
    result = dns_lookup("stalled.test", timeout_seconds=0.01, resolver=stalled)
    elapsed = time.monotonic() - started
    workers = [thread for thread in threading.enumerate() if thread.name == "pte-dns"]

    assert result["status"] == "unavailable"
    assert elapsed < 0.2
    assert workers and all(thread.daemon for thread in workers)
    release.set()


def test_dns_adapter_normalizes_malformed_resolver_output():
    for malformed in (None, [None], [(socket.AF_INET, socket.SOCK_STREAM, 6, "", None)]):
        result = dns_lookup("malformed.test", resolver=lambda _hostname, value=malformed: value)

        assert result["status"] == "error"
        assert result["limitations"] == ["DNS resolver returned malformed output."]


def test_worker_cli_normalizes_database_errors_without_echoing_content(monkeypatch, capsys):
    sensitive = "submitted-secret-content"

    def unavailable(*_args, **_kwargs):
        raise psycopg.OperationalError(f"database rejected {sensitive}")

    monkeypatch.setattr(enrichment_worker, "run_one_shot", unavailable)

    exit_code = enrichment_worker.main(["--tenant-uid", "cust_TEST", "--job-id", "job_TEST"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == "enrichment failed: database unavailable\n"
    assert sensitive not in captured.err


def test_not_found_reputation_without_positive_evidence_is_insufficient_not_benign():
    provider_results = {
        source: {"status": "not_found", "data": {"malicious": False}}
        for source in ("google_safe_browsing", "urlhaus_abusech", "otx")
    }
    contract = build_enrichment_contract(
        target_url="https://example.test/",
        source_type="raw_url",
        provider_results=provider_results,
        dom_html=None,
    )

    assert contract["risk"]["classification"] == "blocked_insufficient_evidence"
    assert contract["risk"]["evidence"] == []
    assert "Reputation coverage incomplete" in " ".join(contract["risk"]["limitations"])
    assert "DOM artifact was unavailable" in " ".join(contract["risk"]["limitations"])


def test_enrichment_persistence_writes_artifact_observations_risk_and_source_status(db, tenant_a, tmp_path):
    submission = create_submission(db, tenant_a, "ocr_text_message", envelope={"fixture": "fedex"})
    job = create_job(db, tenant_a, submission["submission_id"], "ocr_text_message")
    contract = _fedex_contract()
    persisted = persist_enrichment_job(
        db,
        tenant_uid=tenant_a,
        job_id=job["job_id"],
        contract=contract,
        artifact_store=ArtifactStore(tmp_path / "store"),
    )

    bundle = get_job_bundle(db, tenant_a, job["job_id"])
    assert bundle["job"]["state"] == "completed"
    assert persisted["artifact"]["derived_kind"] == "enrichment_payload"
    assert len(bundle["enrichment_observations"]) == len(SOURCE_NAMES)
    assert bundle["risk_scores"][0]["classification"] == "phishing"
    assert bundle["risk_scores"][0]["factors"]["method"] == "deterministic-weighted-evidence-v1"
    assert any(item["source"] == "dom_indicators" for item in bundle["risk_scores"][0]["factors"]["evidence"])
    assert bundle["source_status"][0]["status"] == "enriched"
    assert bundle["source_status"][0]["source_type"] == "ocr_text_message"
    pointer = bundle["derived_artifacts"][0]["storage_pointer"]
    assert (tmp_path / "store" / pointer).is_file()


def test_enrichment_persistence_can_leave_job_analyzing(db, tenant_a, tmp_path):
    submission = create_submission(db, tenant_a, "ocr_text_message", envelope={"fixture": "fedex"})
    job = create_job(db, tenant_a, submission["submission_id"], "ocr_text_message")
    persist_enrichment_job(
        db, tenant_uid=tenant_a, job_id=job["job_id"], contract=_fedex_contract(),
        artifact_store=ArtifactStore(tmp_path / "store"), completion_state="analyzing",
    )

    assert get_job_bundle(db, tenant_a, job["job_id"])["job"]["state"] == "analyzing"


def test_one_shot_safe_worker_loads_queued_job_and_persists_to_postgres(db, tenant_a, tmp_path):
    submission = create_submission(db, tenant_a, "raw_url", envelope={"mode": "safe-local"})
    job = create_job(db, tenant_a, submission["submission_id"], "raw_url")
    add_indicators(db, tenant_a, job["job_id"], [{
        "indicator_type": "url",
        "raw_value": "https://example.test/path",
        "defanged_value": "hxxps://example[.]test/path",
    }])

    result = run_one_shot(
        db, tenant_uid=tenant_a, job_id=str(job["job_id"]),
        artifact_store=ArtifactStore(tmp_path / "worker-store"),
    )
    bundle = get_job_bundle(db, tenant_a, job["job_id"])

    assert bundle["job"]["state"] == "completed"
    assert len(result["observations"]) == len(SOURCE_NAMES)
    assert {row["source"]: row["status"] for row in bundle["enrichment_observations"]}[
        "google_safe_browsing"
    ] == "unavailable"
    assert bundle["risk_scores"]
    assert bundle["source_status"][0]["status"] == "enriched"
