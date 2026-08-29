"""Deterministic OSINT enrichment contract and evidence-based risk scoring.

This module is intentionally passive.  It defines the backend worker output shape
for external OSINT sources without performing live network I/O.  Provider clients
can later populate the same source slots; tests use fixed fixtures so risk
scoring stays explainable and reproducible.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache
from html.parser import HTMLParser
from importlib import resources
from typing import Any
from urllib.parse import unquote, urlsplit

from .artifacts import ArtifactStore
from .services import (
    ValidationError,
    add_derived_artifact,
    add_enrichment_observation,
    add_risk_score,
    get_job_bundle,
    set_job_state,
    set_source_status,
)
from .db import DbConfig

SCHEMA_VERSION = 1
WORKER_NAME = "enrichment-worker"
DEFAULT_OBSERVED_AT = "1970-01-01T00:00:00Z"
SOURCE_NAMES = (
    "dns",
    "rdap_whois",
    "asn_hosting",
    "tls_certificate_transparency",
    "google_safe_browsing",
    "urlhaus_abusech",
    "otx",
    "url_parsing_tricks",
    "domain_age",
    "dom_indicators",
    "source_status",
)
REPUTATION_SOURCES = {
    "google_safe_browsing",
    "urlhaus_abusech",
    "otx",
}
PUBLIC_SUFFIX_RESOURCE = "data/public_suffix_list.dat"


def canonical_json(data: dict[str, Any]) -> bytes:
    """Serialize worker output with deterministic key and whitespace choices."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class EnrichmentEvidence:
    """One explainable scoring input."""

    source: str
    weight: float
    description: str
    observable: str | None = None
    limitation: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "weight": self.weight,
            "description": self.description,
            "observable": self.observable,
            "limitation": self.limitation,
        }


class _DomIndicatorParser(HTMLParser):
    """Small passive DOM feature extractor; it never evaluates scripts."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, Any]] = []
        self.inputs: list[dict[str, str]] = []
        self.buttons: list[str] = []
        self.scripts: list[str] = []
        self.iframes: list[str] = []
        self._current_button = False
        self._button_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {key.lower(): value or "" for key, value in attrs}
        if tag == "form":
            self.forms.append({"action": attr.get("action", ""), "method": attr.get("method", "get")})
        elif tag == "input":
            self.inputs.append({
                "type": attr.get("type", "text").lower(),
                "name": attr.get("name", ""),
                "id": attr.get("id", ""),
                "autocomplete": attr.get("autocomplete", ""),
            })
        elif tag == "button":
            self._current_button = True
            self._button_text = []
        elif tag == "script":
            self.scripts.append(attr.get("src", "inline"))
        elif tag == "iframe":
            self.iframes.append(attr.get("src", ""))

    def handle_data(self, data: str) -> None:
        if self._current_button:
            self._button_text.append(data.strip())

    def handle_endtag(self, tag: str) -> None:
        if tag == "button" and self._current_button:
            text = " ".join(part for part in self._button_text if part)
            if text:
                self.buttons.append(text[:120])
            self._current_button = False
            self._button_text = []


@cache
def _public_suffix_rules() -> dict[str, frozenset[str]]:
    """Load pinned offline Public Suffix List rules from package data."""
    exact: set[str] = set()
    wildcards: set[str] = set()
    exceptions: set[str] = set()
    resource = resources.files("pte").joinpath(PUBLIC_SUFFIX_RESOURCE)
    for raw_line in resource.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip().lower()
        if not line or line.startswith("//"):
            continue
        if line.startswith("!"):
            exceptions.add(line[1:])
        elif line.startswith("*."):
            wildcards.add(line[2:])
        else:
            exact.add(line)
    return {
        "exact": frozenset(exact),
        "wildcards": frozenset(wildcards),
        "exceptions": frozenset(exceptions),
    }


def _public_suffix_label_count(labels: list[str]) -> int:
    """Return the number of labels in the pinned offline public suffix."""
    if not labels:
        return 0
    rules = _public_suffix_rules()
    for index in range(len(labels)):
        suffix = ".".join(labels[index:])
        if suffix in rules["exceptions"]:
            return max(1, len(labels) - index - 1)
    matches = [1]
    for index in range(len(labels)):
        suffix = ".".join(labels[index:])
        if suffix in rules["exact"]:
            matches.append(len(labels) - index)
        if index < len(labels) - 1 and ".".join(labels[index + 1:]) in rules["wildcards"]:
            matches.append(len(labels) - index)
    return max(matches)


def _host_parts(hostname: str | None) -> dict[str, Any]:
    host = (hostname or "").lower().strip(".")
    labels = [label for label in host.split(".") if label]
    public_suffix_labels = _public_suffix_label_count(labels)
    if len(labels) > public_suffix_labels:
        registered_domain_labels = public_suffix_labels + 1
        registered_domain = ".".join(labels[-registered_domain_labels:])
        subdomain = ".".join(labels[:-registered_domain_labels])
    else:
        registered_domain = host
        subdomain = ""
    return {"host": host, "registered_domain": registered_domain, "subdomain": subdomain}


def _normalized_field_text(field: dict[str, str]) -> str:
    """Normalize DOM identifiers so regex terms match camel/snake/kebab names."""
    raw = " ".join([field["type"], field["name"], field["id"], field["autocomplete"]])
    split_camel = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", raw)
    split_nonword = re.sub(r"[^A-Za-z0-9]+", " ", split_camel)
    return " ".join(split_nonword.lower().split())


def analyze_url(url: str, *, brand_terms: list[str] | None = None) -> dict[str, Any]:
    """Return URL decomposition and passive parsing-trick indicators."""
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        parsed = urlsplit("")
        port = None
    parts = _host_parts(parsed.hostname)
    host = parts["host"]
    path_query = unquote((parsed.path or "") + ("?" + parsed.query if parsed.query else ""))
    tricks: list[dict[str, Any]] = []
    if parsed.username or parsed.password or "@" in parsed.netloc:
        tricks.append({"name": "userinfo_present", "severity": "high",
                       "evidence": "URL authority contains userinfo or @ delimiter"})
    if port not in {None, 80, 443}:
        tricks.append({"name": "non_default_port", "severity": "medium",
                       "evidence": f"URL specifies TCP port {port}"})
    if host.startswith("xn--") or ".xn--" in host:
        tricks.append({"name": "punycode_idn", "severity": "medium",
                       "evidence": "hostname contains IDNA punycode label"})
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-f:]+\]", host):
        tricks.append({"name": "ip_literal_host", "severity": "medium",
                       "evidence": "URL uses an IP literal instead of a domain"})
    brands = [term.lower() for term in (brand_terms or []) if term.strip()]
    for brand in brands:
        if brand in host and brand not in parts["registered_domain"]:
            tricks.append({"name": "brand_in_subdomain", "severity": "high",
                           "evidence": f"{brand!r} appears outside the registrable domain"})
        if brand in path_query.lower() and brand not in host:
            tricks.append({"name": "brand_in_path", "severity": "medium",
                           "evidence": f"{brand!r} appears in URL path/query but not hostname"})
    return {
        "url": url,
        "scheme": parsed.scheme,
        "host": host,
        "registered_domain": parts["registered_domain"],
        "subdomain": parts["subdomain"],
        "path_depth": len([part for part in parsed.path.split("/") if part]),
        "query_keys": sorted(key for key in (item.split("=", 1)[0] for item in parsed.query.split("&")) if key),
        "tricks": sorted(tricks, key=lambda item: (item["name"], item["evidence"])),
    }


def analyze_dom(html: str | None) -> dict[str, Any]:
    """Extract credential/card/OTP indicators from inert DOM text."""
    if html is None:
        return {
            "available": False,
            "credential_fields": [],
            "card_fields": [],
            "otp_fields": [],
            "forms": [],
            "scripts": [],
            "iframes": [],
            "limitations": ["DOM artifact was unavailable; page implementation indicators were not evaluated."],
        }
    parser = _DomIndicatorParser()
    parser.feed(html)
    credential_fields: list[dict[str, str]] = []
    card_fields: list[dict[str, str]] = []
    otp_fields: list[dict[str, str]] = []
    for field in parser.inputs:
        haystack = _normalized_field_text(field)
        if field["type"] == "password" or re.search(r"\b(pass(word|code)?|login|user(name)?|email)\b", haystack):
            credential_fields.append(field)
        if re.search(r"\b(card|cc|cvv|cvc|expiry|exp|billing)\b", haystack):
            card_fields.append(field)
        if re.search(r"\b(otp|mfa|2fa|one\s*time|verification|security\s*code)\b", haystack):
            otp_fields.append(field)
    support_terms = [text for text in parser.buttons if re.search(r"chat|support|agent|help|verify|continue", text, re.I)]
    return {
        "available": True,
        "credential_fields": credential_fields,
        "card_fields": card_fields,
        "otp_fields": otp_fields,
        "forms": parser.forms,
        "scripts": sorted(parser.scripts),
        "iframes": sorted(parser.iframes),
        "support_or_verification_buttons": sorted(support_terms),
        "limitations": ["DOM was parsed statically; JavaScript event handlers were not executed."],
    }


def source_result(
    source: str,
    *,
    status: str,
    observable: str,
    provider: str | None = None,
    data: dict[str, Any] | None = None,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    """Build one normalized source result with explicit status and limitations."""
    if source not in SOURCE_NAMES:
        raise ValidationError(f"unknown enrichment source: {source!r}")
    if status not in {"ok", "not_found", "unavailable", "blocked", "error"}:
        raise ValidationError(f"invalid enrichment status: {status!r}")
    return {
        "source": source,
        "provider": provider or source,
        "status": status,
        "observable": observable,
        "data": data or {},
        "limitations": limitations or [],
    }


def _provider_sources(provider_results: dict[str, dict[str, Any]], observable: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for source in SOURCE_NAMES:
        if source in {"url_parsing_tricks", "dom_indicators", "source_status"}:
            continue
        item = provider_results.get(source)
        if item is None:
            results.append(source_result(
                source, status="unavailable", observable=observable,
                limitations=["No provider result was supplied to the deterministic worker."],
            ))
            continue
        results.append(source_result(
            source,
            status=item.get("status", "ok"),
            observable=item.get("observable", observable),
            provider=item.get("provider") or source,
            data=item.get("data") or {},
            limitations=item.get("limitations") or [],
        ))
    return results


def score_enrichment(contract: dict[str, Any]) -> dict[str, Any]:
    """Create an explainable 0-100 risk score from normalized source results."""
    evidence: list[EnrichmentEvidence] = []
    limitations: list[str] = []
    source_statuses = {item["source"]: item["status"] for item in contract["sources"]}
    by_source = {item["source"]: item for item in contract["sources"]}

    unavailable_reputation = [src for src in REPUTATION_SOURCES if source_statuses.get(src) != "ok"]
    if unavailable_reputation:
        limitations.append("Reputation coverage incomplete: " + ", ".join(sorted(unavailable_reputation)))

    url_tricks = by_source["url_parsing_tricks"]["data"].get("tricks", [])
    for trick in url_tricks:
        weight = 16.0 if trick["severity"] == "high" else 8.0
        evidence.append(EnrichmentEvidence("url_parsing_tricks", weight, trick["evidence"], trick["name"]))

    dom = by_source["dom_indicators"]["data"]
    if dom.get("credential_fields"):
        evidence.append(EnrichmentEvidence("dom_indicators", 24.0, "DOM contains credential/login fields", "credential_fields"))
    if dom.get("otp_fields"):
        evidence.append(EnrichmentEvidence("dom_indicators", 18.0, "DOM requests OTP/MFA/security-code data", "otp_fields"))
    if dom.get("card_fields"):
        evidence.append(EnrichmentEvidence("dom_indicators", 22.0, "DOM requests payment-card data", "card_fields"))
    if dom.get("support_or_verification_buttons"):
        evidence.append(EnrichmentEvidence("dom_indicators", 6.0, "DOM includes support/verification CTA text", "support_or_verification_buttons"))
    if not dom.get("available"):
        limitations.extend(dom.get("limitations", []))

    age = by_source["domain_age"]["data"]
    days_old = age.get("days_old")
    if isinstance(days_old, int) and days_old <= 30:
        evidence.append(EnrichmentEvidence("domain_age", 14.0, f"Domain age is {days_old} days", "days_old"))
    elif isinstance(days_old, int) and days_old <= 180:
        evidence.append(EnrichmentEvidence("domain_age", 6.0, f"Domain age is {days_old} days", "days_old"))

    for source in REPUTATION_SOURCES:
        data = by_source[source]["data"]
        if data.get("malicious") is True or data.get("verdict") in {"malicious", "phishing"}:
            evidence.append(EnrichmentEvidence(source, 25.0, f"{source} reports malicious/phishing reputation"))
        elif source_statuses.get(source) == "ok":
            evidence.append(EnrichmentEvidence(source, -3.0, f"{source} returned no known malicious match"))

    dns = by_source["dns"]["data"]
    if dns.get("newly_seen") is True:
        evidence.append(EnrichmentEvidence("dns", 5.0, "DNS data indicates newly seen infrastructure"))
    asn = by_source["asn_hosting"]["data"]
    if asn.get("hosting_risk") in {"bulletproof", "abuse-prone", "dynamic"}:
        evidence.append(EnrichmentEvidence("asn_hosting", 8.0, "Hosting/ASN has elevated abuse context", asn.get("hosting_risk")))
    cert = by_source["tls_certificate_transparency"]["data"]
    if cert.get("brand_terms_in_recent_sans"):
        evidence.append(EnrichmentEvidence("tls_certificate_transparency", 8.0, "Recent certificate SANs contain brand terms"))

    score = max(0.0, min(100.0, round(sum(item.weight for item in evidence), 2)))
    positive = sum(1 for item in evidence if item.weight > 0)
    high_signal = any(item.weight >= 18 for item in evidence)
    insufficient_coverage = bool(unavailable_reputation) or not dom.get("available")
    has_affirmative_benign_evidence = any(item.weight < 0 for item in evidence)
    if score >= 70 or (high_signal and score >= 55):
        classification = "phishing"
    elif score >= 35 or positive >= 3:
        classification = "suspicious"
    elif not evidence and insufficient_coverage and not has_affirmative_benign_evidence:
        classification = "blocked_insufficient_evidence"
    else:
        classification = "benign"
    confidence = 0.35 + min(0.35, 0.05 * len([s for s in source_statuses.values() if s == "ok"]))
    if dom.get("available"):
        confidence += 0.15
    if unavailable_reputation:
        confidence -= 0.05 * len(unavailable_reputation)
    confidence = max(0.05, min(0.95, round(confidence, 2)))
    return {
        "classification": classification,
        "score": score,
        "confidence": confidence,
        "evidence": [item.as_dict() for item in evidence],
        "limitations": sorted(set(limitations + [lim for src in contract["sources"] for lim in src.get("limitations", [])])),
        "method": "deterministic-weighted-evidence-v1",
    }


def build_enrichment_contract(
    *,
    target_url: str,
    source_type: str,
    provider_results: dict[str, dict[str, Any]] | None = None,
    dom_html: str | None = None,
    brand_terms: list[str] | None = None,
    observed_at: str = DEFAULT_OBSERVED_AT,
) -> dict[str, Any]:
    """Build the complete deterministic worker JSON contract."""
    url = analyze_url(target_url, brand_terms=brand_terms)
    observable = url["registered_domain"] or url["host"] or target_url
    sources = _provider_sources(provider_results or {}, observable)
    sources.append(source_result("url_parsing_tricks", status="ok", observable=target_url, data=url))
    sources.append(source_result("dom_indicators", status="ok" if dom_html is not None else "unavailable",
                                 observable=target_url, data=analyze_dom(dom_html)))
    sources.append(source_result("source_status", status="ok", observable=source_type,
                                 data={"source_type": source_type, "status": "enriched"}))
    sources = sorted(sources, key=lambda item: item["source"])
    contract = {
        "schema_version": SCHEMA_VERSION,
        "worker": WORKER_NAME,
        "observed_at": observed_at,
        "target": {
            "url": target_url,
            "host": url["host"],
            "registered_domain": url["registered_domain"],
            "source_type": source_type,
        },
        "sources": sources,
    }
    contract["risk"] = score_enrichment(contract)
    return contract


def persist_enrichment_job(
    cfg: DbConfig,
    *,
    tenant_uid: str,
    job_id: uuid.UUID | str,
    contract: dict[str, Any],
    artifact_store: ArtifactStore | None = None,
    actor: str = WORKER_NAME,
) -> dict[str, Any]:
    """Persist enrichment artifact, observations, risk score, and source status."""
    bundle = get_job_bundle(cfg, tenant_uid, job_id)
    submission_id = bundle["job"]["submission_id"]
    if contract.get("schema_version") != SCHEMA_VERSION:
        raise ValidationError("unsupported enrichment schema version")
    data = canonical_json(contract)
    store = artifact_store or ArtifactStore()
    pointer = store.put(tenant_uid, data)
    set_job_state(cfg, tenant_uid, job_id, "analyzing", actor=actor, reason="enrichment started")
    raw = add_derived_artifact(
        cfg, tenant_uid, job_id, submission_id, "enrichment_payload",
        "application/json", data, pointer, actor, tool_version=f"contract-v{SCHEMA_VERSION}",
    )
    observations = []
    for source in contract["sources"]:
        observations.append(add_enrichment_observation(
            cfg, tenant_uid, job_id, source["provider"], source["source"], source["status"],
            result=source["data"], observable_value=source["observable"],
            raw_artifact_id=raw["derived_id"],
        ))
    risk = contract["risk"]
    persisted_risk = add_risk_score(
        cfg, tenant_uid, job_id, risk["classification"], risk["confidence"], risk["score"],
        factors={"method": risk["method"], "evidence": risk["evidence"],
                 "limitations": risk["limitations"]},
        created_by=actor,
    )
    source_status = set_source_status(
        cfg, tenant_uid, job_id, contract["target"]["source_type"], "enriched",
        {"artifact_sha256": raw["sha256"], "risk_score_id": persisted_risk["risk_score_id"],
         "classification": risk["classification"], "limitations": risk["limitations"]},
    )
    set_job_state(cfg, tenant_uid, job_id, "completed", actor=actor, reason="enrichment persisted")
    return {
        "artifact": raw,
        "observations": observations,
        "risk_score": persisted_risk,
        "source_status": source_status,
    }


def utc_observed_at() -> str:
    """Return an RFC3339 UTC timestamp for live worker runs."""
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
