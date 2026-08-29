"""Deterministic, redacted analyst report assembly and rendering."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import unicodedata
from datetime import date, datetime
from typing import Any
from urllib.parse import urlsplit

from .enrichment import SOURCE_NAMES

REPORT_SCHEMA = "pte.analyst-content-pack"
REPORT_VERSION = "1.0"


_SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,160}\Z")
_SAFE_PROVIDER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_-]{0,78}[A-Za-z0-9])?\Z")
_CREDENTIAL_MARKER = re.compile(
    r"(?:bearer|credential|password|secret|token|api[_-]?key)", re.IGNORECASE
)
_SAFE_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
_DOMAIN_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_EMAIL_LOCAL = re.compile(r"[A-Za-z0-9.!$%&'+=?^~-]{1,64}\Z")
_HEX_HASH_LENGTHS = frozenset({32, 40, 64, 128})
_UNSAFE_INDICATOR_TEXT = re.compile(r"[\x00-\x1f\x7f`*_{}\[\]()<>#!|\\]")
_REDACTED_INDICATOR = "[redacted indicator]"


def _identifier(value: Any, fallback: str = "unknown") -> str:
    """Accept only opaque identifiers, never arbitrary display text."""
    text = str(value) if value is not None else ""
    return text if _SAFE_IDENTIFIER.fullmatch(text) else fallback


def _choice(value: Any, allowed: frozenset[str], fallback: str = "unknown") -> str:
    """Return a value only when it belongs to a report-owned vocabulary."""
    return value if isinstance(value, str) and value in allowed else fallback


def _provider_identifier(value: Any, fallback: str = "unknown") -> str:
    """Keep bounded provider labels, excluding free text and credential markers."""
    if not isinstance(value, str) or not _SAFE_PROVIDER.fullmatch(value):
        return fallback
    return fallback if _CREDENTIAL_MARKER.search(value) else value


ARTIFACT_KINDS = frozenset({
    "attachment", "email", "email_body", "har", "ocr_output", "ocr_text",
    "redirect_chain", "report_file", "screenshot", "screenshot_capture",
})
MEDIA_TYPES = frozenset({"application/json", "application/pdf", "message/rfc822",
                         "image/gif", "image/jpeg", "image/png", "image/webp",
                         "text/html", "text/plain"})
SOURCE_TYPES = frozenset(SOURCE_NAMES) | frozenset({
    "raw_url", "email_artifact", "ocr_text_message", "screenshot_evidence",
})
STATUSES = frozenset({"blocked", "completed", "enriched", "error", "failed",
                      "not_found", "ok", "parsed", "partial", "pending", "queued",
                      "received", "scan_pending", "scanned", "skipped", "unavailable",
                      "unknown", "unreachable"})
CLASSIFICATIONS = frozenset({"benign", "blocked_insufficient_evidence", "malware_delivery",
                             "phishing", "suspicious", "unknown"})


def _timestamp(value: Any) -> str | None:
    """Render backend timestamps deterministically without inventing a value."""
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
        except ValueError:
            return None
    return None


def _validated_domain(value: str) -> str | None:
    """Return a normalized strict ASCII DNS name, or fail closed."""
    if not value or len(value) > 253 or value.endswith("."):
        return None
    labels = value.split(".")
    if len(labels) < 2 or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        return None
    return value.lower()


def _defanged_host(value: str) -> str | None:
    """Validate a URL host as either an IP literal or strict DNS name."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        domain = _validated_domain(value)
        return domain.replace(".", "[.]") if domain else None
    rendered = address.compressed
    return rendered.replace(".", "[.]").replace(":", "[:]")


def defang_indicator(indicator_type: str, raw_value: str) -> str:
    """Render only validated IOCs, suppressing all untrusted IOC detail on failure."""
    if not isinstance(raw_value, str):
        return _REDACTED_INDICATOR
    if (_UNSAFE_INDICATOR_TEXT.search(raw_value)
            or any(unicodedata.category(ch) == "Cc" for ch in raw_value)):
        return _REDACTED_INDICATOR
    value = raw_value.strip()
    if not value:
        return _REDACTED_INDICATOR
    if indicator_type == "url":
        try:
            parsed = urlsplit(value)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
                return _REDACTED_INDICATOR
            host = _defanged_host(parsed.hostname or "")
            if not host:
                return _REDACTED_INDICATOR
            port = f":{parsed.port}" if parsed.port else ""
            scheme = "hxxps" if parsed.scheme.lower() == "https" else "hxxp"
            suffix = "/[…redacted…]" if (
                parsed.path not in {"", "/"} or parsed.query or parsed.fragment
            ) else ""
            return f"{scheme}://{host}{port}{suffix}"
        except (ValueError, UnicodeError):
            return _REDACTED_INDICATOR
    if indicator_type in {"domain", "hostname"}:
        domain = _validated_domain(value)
        return domain.replace(".", "[.]") if domain else _REDACTED_INDICATOR
    if indicator_type == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return _REDACTED_INDICATOR
        return address.compressed.replace(".", "[.]").replace(":", "[:]")
    if indicator_type == "email_address":
        if value.count("@") != 1:
            return _REDACTED_INDICATOR
        local, raw_domain = value.split("@")
        domain = _validated_domain(raw_domain)
        if (not domain or not _EMAIL_LOCAL.fullmatch(local) or local.startswith(".")
                or local.endswith(".") or ".." in local):
            return _REDACTED_INDICATOR
        return f"***@{domain.replace('.', '[.]')}"
    if indicator_type == "phone_number":
        digits = "".join(ch for ch in value if ch.isdigit())
        return f"***-***-{digits[-4:]}" if len(digits) >= 4 else "[redacted phone]"
    if indicator_type == "file_hash":
        if len(value) in _HEX_HASH_LENGTHS and re.fullmatch(r"[0-9a-fA-F]+", value):
            return value.lower()
        return _REDACTED_INDICATOR
    return _REDACTED_INDICATOR


def _artifact_reference(row: dict[str, Any], *, derived: bool = False) -> dict[str, Any]:
    reference = {
        "artifact_id": _identifier(row["derived_id"] if derived else row["artifact_id"]),
        "kind": _choice(row.get("derived_kind") if derived else row.get("artifact_type"), ARTIFACT_KINDS),
        "media_type": _choice(row.get("media_type"), MEDIA_TYPES),
        "sha256": str(row.get("sha256")) if _SAFE_SHA256.fullmatch(str(row.get("sha256", ""))) else "unknown",
        "relationship": "derived" if derived else "submitted",
    }
    captured_at = _timestamp(row.get("produced_at") if derived else row.get("captured_at"))
    if captured_at is not None:
        reference["captured_at"] = captured_at
    if isinstance(row.get("byte_size"), int) and row["byte_size"] >= 0:
        reference["byte_size"] = row["byte_size"]
    return reference


def assemble_content_pack(bundle: dict[str, Any]) -> dict[str, Any]:
    """Assemble a safe content pack solely from a tenant-scoped job bundle."""
    job = bundle["job"]
    inputs = [_artifact_reference(row) for row in bundle.get("input_artifacts", [])]
    derived = [
        _artifact_reference(row, derived=True)
        for row in bundle.get("derived_artifacts", [])
        if row.get("derived_kind") != "report_file"
    ]
    screenshots = [
        ref for ref in inputs + derived
        if ref["kind"] in {"screenshot", "screenshot_capture"}
        or ref["media_type"].startswith("image/")
    ]
    indicators = []
    for row in bundle.get("indicators", []):
        raw = str(row.get("raw_value") or "")
        provenance = _choice(row.get("provenance"), frozenset({"ocr_derived", "submitted", "derived"}))
        indicators.append({
            "type": _choice(row.get("indicator_type"), frozenset({"domain", "email_address", "file_hash", "hostname", "ip", "phone_number", "url"})),
            "value": defang_indicator(_choice(row.get("indicator_type"), frozenset({"domain", "email_address", "file_hash", "hostname", "ip", "phone_number", "url"})), raw),
            "value_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            "provenance": provenance,
            "provenance_label": "OCR-derived; transcription unverified"
            if provenance == "ocr_derived" else "Observed in submitted or derived evidence",
            "corroboration_status": _choice(row.get("corroboration_status"), frozenset({"corroborated", "unverified"}), "unverified"),
        })
    indicators.sort(key=lambda item: (item["type"], item["value"], item["value_sha256"]))

    risks = bundle.get("risk_scores", [])
    risk = risks[-1] if risks else None
    limitations: list[str] = []
    if not risk:
        limitations.append("No risk score was available; classification is insufficient evidence.")
    if not bundle.get("enrichment_observations"):
        limitations.append("No enrichment observations were available.")
    if not bundle.get("scan_events"):
        limitations.append("No scanner evidence was available; no live behavior is asserted.")
    if any(item["provenance"] == "ocr_derived" for item in indicators):
        limitations.append("OCR-derived indicators may contain transcription errors and require corroboration.")
    if not inputs:
        limitations.append("No submitted artifact references were available.")
    if job.get("fidelity") in {"partial", "low"}:
        limitations.append(
            f"Submission fidelity was {_choice(job.get('fidelity'), frozenset({'partial', 'low'}))}; original context may be incomplete."
        )

    classification = _choice(risk.get("classification"), CLASSIFICATIONS) if risk else "blocked_insufficient_evidence"
    confidence = float(risk["confidence"]) if risk and risk.get("confidence") is not None else 0.0
    score = float(risk["score"]) if risk and risk.get("score") is not None else 0.0
    finding = (
        f"Assessment: {classification.replace('_', ' ')} based on {len(inputs) + len(derived)} "
        "referenced evidence artifact(s)."
        if risk else "Insufficient evidence for a substantive phishing determination."
    )

    sources = [{
        "source": _choice(row.get("source"), SOURCE_TYPES),
        "provider": _provider_identifier(row.get("provider")),
        "status": _choice(row.get("status"), STATUSES),
        "fact": "Provider lookup status was recorded.",
    } for row in bundle.get("enrichment_observations", [])]
    sources.extend({
        "source": _choice(row.get("source_type"), SOURCE_TYPES), "provider": "internal pipeline",
        "status": _choice(row.get("status"), STATUSES), "fact": "Pipeline source status was recorded.",
    } for row in bundle.get("source_status", []))
    if not sources:
        sources.append({"source": "enrichment", "provider": "none", "status": "unavailable",
                        "fact": "No source status was recorded."})
    sources.sort(key=lambda item: (item["source"], item["provider"], item["status"]))

    phishing = classification in {"phishing", "malware_delivery", "suspicious"}
    ttps = ([
        {"id": "T1566", "name": "Phishing", "basis": "inference",
         "rationale": "The risk assessment and submitted lure indicators are consistent with phishing."},
        {"id": "T1204", "name": "User Execution", "basis": "inference",
         "rationale": "The lure appears intended to persuade a recipient to follow an external link."},
    ] if phishing and indicators else [])
    recommendations = [
        "Do not visit, reply to, call, or submit credentials or payment information to reported indicators.",
        "Block the listed defanged indicators after validating scope and business impact.",
        "Search tenant telemetry for the IOC SHA-256 references and securely retained raw evidence.",
        "Reset credentials and revoke sessions only for users confirmed to have interacted with the lure.",
        "Preserve original evidence and escalate confirmed compromise through the incident-response process.",
    ]
    caveats = limitations or ["This report is a point-in-time defensive assessment, not proof of compromise."]
    return {
        "schema": REPORT_SCHEMA, "version": REPORT_VERSION,
        "tenant_uid": _identifier(job["tenant_uid"]), "job_id": _identifier(job["job_id"]),
        "submission_id": _identifier(job["submission_id"]),
        "job": {"source_type": _choice(job.get("source_type"), SOURCE_TYPES),
                "state": _choice(job.get("state"), STATUSES)},
        "submission": {
            "fidelity": _choice(job.get("fidelity"), frozenset({"full", "low", "partial"})),
            "submitted_at": _timestamp(job.get("submitted_at")),
        },
        "executive_summary": {
            "classification": classification, "confidence": confidence, "score": score,
            "finding": finding, "evidence_count": len(inputs) + len(derived),
            "limitations": caveats,
        },
        "observed_facts": {
            "submitted_evidence": inputs, "derived_artifacts": derived,
            "screenshot_references": screenshots, "iocs": indicators,
            "source_status": sources,
        },
        "inferences": {"ttps": ttps, "assessment": finding},
        "safety_controls": [
            "All IOCs are defanged; URL paths and queries are suppressed.",
            "Raw submitted bodies, URLs, tokens, PII, storage pointers, and filesystem paths are excluded.",
            "No credential submission, account contact, public scanner, or browser interaction is performed.",
        ],
        "analyst_caveats": caveats,
        "defensive_recommendations": recommendations,
    }


def render_json(pack: dict[str, Any]) -> str:
    """Return canonical UTF-8 JSON with stable key and list ordering."""
    return json.dumps(pack, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"


def render_markdown(pack: dict[str, Any]) -> str:
    """Render a deterministic Markdown analyst report."""
    summary = pack["executive_summary"]
    facts = pack["observed_facts"]
    lines = [
        "# Phishing Triage Analyst Report", "",
        f"Schema: `{pack['schema']}`  ", f"Version: `{pack['version']}`  ",
        f"Tenant: `{pack['tenant_uid']}`  ", f"Job: `{pack['job_id']}`  ",
        f"Submission: `{pack['submission_id']}`  ",
        f"Source type: `{pack['job']['source_type']}`  ",
        f"Job state at assembly: `{pack['job']['state']}`", "", "## Executive summary", "",
        f"- Classification: {summary['classification']}",
        f"- Confidence: {summary['confidence']:.4f}", f"- Score: {summary['score']:.2f}",
        f"- Finding: {summary['finding']}", f"- Evidence references: {summary['evidence_count']}",
        "", "## Observed facts", "", "### Evidence references", "",
    ]
    refs = facts["submitted_evidence"] + facts["derived_artifacts"]
    lines.extend(f"- `{r['artifact_id']}` — {r['kind']}; SHA-256 `{r['sha256']}`" for r in refs)
    if not refs:
        lines.append("- None available.")
    lines.extend(["", "### Screenshot references", ""])
    lines.extend(f"- `{r['artifact_id']}` — SHA-256 `{r['sha256']}`" for r in facts["screenshot_references"])
    if not facts["screenshot_references"]:
        lines.append("- None available.")
    lines.extend(["", "### Defanged IOCs", ""])
    lines.extend(f"- {i['type']}: `{i['value']}` — {i['provenance_label']}; value SHA-256 `{i['value_sha256']}`" for i in facts["iocs"])
    if not facts["iocs"]:
        lines.append("- None available.")
    lines.extend(["", "### Enrichment and source status", ""])
    lines.extend(
        f"- {s['source']} / {s['provider']}: {s['status']} — {s['fact']}"
        + (f" Limitation: {s['limitation']}" if s.get("limitation") else "")
        for s in facts["source_status"]
    )
    lines.extend(["", "## Inferences (not directly observed)", ""])
    lines.extend(f"- {t['id']} {t['name']}: {t['rationale']}" for t in pack["inferences"]["ttps"])
    if not pack["inferences"]["ttps"]:
        lines.append("- No TTP inference supported by the available evidence.")
    for heading, key in (("Safety controls", "safety_controls"), ("Analyst caveats", "analyst_caveats"),
                         ("Defensive recommendations", "defensive_recommendations")):
        lines.extend(["", f"## {heading}", ""])
        lines.extend(f"- {value}" for value in pack[key])
    return "\n".join(lines) + "\n"
