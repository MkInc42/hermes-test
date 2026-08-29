"""Deterministic, redacted analyst report assembly and rendering."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date, datetime
from typing import Any
from urllib.parse import urlsplit

REPORT_SCHEMA = "pte.analyst-content-pack"
REPORT_VERSION = "1.0"


def _text(value: Any, fallback: str = "unknown") -> str:
    """Return a bounded, single-line label, never arbitrary structured input."""
    if not isinstance(value, str) or not value.strip():
        return fallback
    return " ".join(value.strip().split())[:160]


def _timestamp(value: Any) -> str | None:
    """Render backend timestamps deterministically without inventing a value."""
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, str) and value.strip():
        return _text(value)
    return None


def _safe_detail(value: Any) -> str | None:
    """Keep a useful status limitation while suppressing common sensitive values."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = " ".join(value.strip().split())
    text = re.sub(r"(?i)\bhttps?://\S+", "[redacted URL]", text)
    text = re.sub(r"(?i)\b[^\s@]+@[^\s@]+\b", "[redacted email]", text)
    text = re.sub(r"(?i)\bstorage_pointer\s*[:=]\s*\S+", "storage pointer [redacted]", text)
    text = re.sub(r"(?<!\w)(?:/[\w.-]+){2,}", "[redacted path]", text)
    return text[:240]


def defang_indicator(indicator_type: str, raw_value: str) -> str:
    """Render an IOC inert while suppressing URL paths, queries, and PII."""
    value = raw_value.strip()
    if indicator_type == "url":
        try:
            parsed = urlsplit(value)
            host = (parsed.hostname or "").replace(".", "[.]")
            if not host:
                return "[redacted malformed URL]"
            port = f":{parsed.port}" if parsed.port else ""
            scheme = "hxxps" if parsed.scheme.lower() == "https" else "hxxp"
            suffix = "/[…redacted…]" if parsed.path not in {"", "/"} or parsed.query else ""
            return f"{scheme}://{host}{port}{suffix}"
        except (ValueError, UnicodeError):
            return "[redacted malformed URL]"
    if indicator_type in {"domain", "hostname"}:
        return value.lower().replace(".", "[.]")[:253]
    if indicator_type == "ip":
        return value.replace(".", "[.]").replace(":", "[:]")[:80]
    if indicator_type == "email_address":
        domain = value.rsplit("@", 1)[-1] if "@" in value else "redacted.invalid"
        return f"***@{domain.lower().replace('.', '[.]')}"
    if indicator_type == "phone_number":
        digits = "".join(ch for ch in value if ch.isdigit())
        return f"***-***-{digits[-4:]}" if len(digits) >= 4 else "[redacted phone]"
    if indicator_type == "file_hash":
        return value.lower()[:128]
    return "[redacted indicator]"


def _artifact_reference(row: dict[str, Any], *, derived: bool = False) -> dict[str, Any]:
    reference = {
        "artifact_id": str(row["derived_id"] if derived else row["artifact_id"]),
        "kind": _text(row.get("derived_kind") if derived else row.get("artifact_type")),
        "media_type": _text(row.get("media_type")),
        "sha256": _text(row.get("sha256")),
        "relationship": "derived" if derived else "submitted",
    }
    captured_at = _timestamp(row.get("produced_at") if derived else row.get("captured_at"))
    if captured_at is not None:
        reference["captured_at"] = captured_at
    if isinstance(row.get("byte_size"), int) and row["byte_size"] >= 0:
        reference["byte_size"] = row["byte_size"]
    return reference


def _source_detail(row: dict[str, Any]) -> str | None:
    details = row.get("status_detail") or row.get("result")
    if not isinstance(details, dict):
        return None
    for key in ("limitation", "limitations", "reason", "error_class", "message"):
        value = details.get(key)
        if isinstance(value, list):
            value = "; ".join(str(item) for item in value if isinstance(item, str))
        safe = _safe_detail(value)
        if safe:
            return safe
    return None


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
        provenance = _text(row.get("provenance"))
        indicators.append({
            "type": _text(row.get("indicator_type")),
            "value": defang_indicator(_text(row.get("indicator_type")), raw),
            "value_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            "provenance": provenance,
            "provenance_label": "OCR-derived; transcription unverified"
            if provenance == "ocr_derived" else "Observed in submitted or derived evidence",
            "corroboration_status": _text(row.get("corroboration_status"), "unverified"),
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
            f"Submission fidelity was {_text(job.get('fidelity'))}; original context may be incomplete."
        )

    classification = _text(risk.get("classification")) if risk else "blocked_insufficient_evidence"
    confidence = float(risk["confidence"]) if risk and risk.get("confidence") is not None else 0.0
    score = float(risk["score"]) if risk and risk.get("score") is not None else 0.0
    finding = (
        f"Assessment: {classification.replace('_', ' ')} based on {len(inputs) + len(derived)} "
        "referenced evidence artifact(s)."
        if risk else "Insufficient evidence for a substantive phishing determination."
    )

    sources = [{
        "source": _text(row.get("source")), "provider": _text(row.get("provider")),
        "status": _text(row.get("status")), "fact": "Provider lookup status was recorded.",
        **({"limitation": detail} if (detail := _source_detail(row)) else {}),
    } for row in bundle.get("enrichment_observations", [])]
    sources.extend({
        "source": _text(row.get("source_type")), "provider": "internal pipeline",
        "status": _text(row.get("status")), "fact": "Pipeline source status was recorded.",
        **({"limitation": detail} if (detail := _source_detail(row)) else {}),
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
        "tenant_uid": str(job["tenant_uid"]), "job_id": str(job["job_id"]),
        "submission_id": str(job["submission_id"]),
        "job": {"source_type": _text(job.get("source_type")),
                "state": _text(job.get("state"))},
        "submission": {
            "case_reference": _text(job.get("case_reference"), "not provided"),
            "fidelity": _text(job.get("fidelity")),
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
