"""One-shot CLI for enriching and persisting one existing queued tenant job."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import psycopg

from .adapters import dns_lookup, unavailable_provider_results
from .artifacts import ArtifactStore
from .db import DbConfig
from .enrichment import build_enrichment_contract, persist_enrichment_job, utc_observed_at
from .services import CrossTenantAccessError, PersistenceError, get_job_bundle

DEFAULT_FIXTURE = Path(__file__).resolve().parent.parent / "tests/fixtures/fedex_smishing_case.json"


def _target_url(bundle: dict[str, Any]) -> str:
    """Select the first persisted URL indicator without reading raw artifacts."""
    for indicator in bundle["indicators"]:
        if indicator["indicator_type"] == "url" and indicator["raw_value"]:
            return str(indicator["raw_value"])
    raise ValueError("queued job has no persisted URL indicator; use --fixture for the safe demo")


def _load_fixture(path: Path) -> dict[str, Any]:
    """Load an offline fixture and reject malformed top-level values."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not load fixture {path}: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("target_url"), str):
        raise ValueError("fixture must be an object containing target_url")
    return value


def run_one_shot(
    cfg: DbConfig,
    *,
    tenant_uid: str,
    job_id: str,
    fixture_path: Path | None = None,
    enable_dns: bool = False,
    dns_timeout: float = 2.0,
    artifact_store: ArtifactStore | None = None,
) -> dict[str, Any]:
    """Load one queued job, enrich it once, and persist all normalized results."""
    bundle = get_job_bundle(cfg, tenant_uid, job_id)
    if bundle["job"]["state"] != "queued":
        raise ValueError(f"job must be queued, found {bundle['job']['state']!r}")

    fixture = _load_fixture(fixture_path) if fixture_path else None
    target_url = str(fixture["target_url"]) if fixture else _target_url(bundle)
    source_type = str(bundle["job"]["source_type"])
    provider_results = (
        dict(fixture.get("provider_results", {}))
        if fixture else unavailable_provider_results(target_url)
    )
    dom_html = fixture.get("dom_html") if fixture else None
    brand_terms = fixture.get("brand_terms") if fixture else None

    if enable_dns:
        # DNS is the only live path and is explicitly operator-enabled.
        from urllib.parse import urlsplit
        hostname = urlsplit(target_url).hostname or ""
        provider_results["dns"] = dns_lookup(hostname, timeout_seconds=dns_timeout)

    contract = build_enrichment_contract(
        target_url=target_url,
        source_type=source_type,
        provider_results=provider_results,
        dom_html=dom_html,
        brand_terms=brand_terms,
        observed_at=utc_observed_at(),
    )
    return persist_enrichment_job(
        cfg, tenant_uid=tenant_uid, job_id=job_id, contract=contract,
        artifact_store=artifact_store,
    )


def main(argv: list[str] | None = None) -> int:
    """Parse worker arguments and return a shell-friendly exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant-uid", required=True)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--fixture", nargs="?", const=str(DEFAULT_FIXTURE), type=Path)
    parser.add_argument("--enable-dns", action="store_true")
    parser.add_argument("--dns-timeout", type=float, default=2.0)
    args = parser.parse_args(argv)
    try:
        result = run_one_shot(
            DbConfig.from_env(), tenant_uid=args.tenant_uid, job_id=args.job_id,
            fixture_path=args.fixture, enable_dns=args.enable_dns,
            dns_timeout=args.dns_timeout,
        )
    except psycopg.Error:
        print("enrichment failed: database unavailable", file=sys.stderr)
        return 1
    except (CrossTenantAccessError, PersistenceError, ValueError, OSError) as exc:
        print(f"enrichment failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"persisted {len(result['observations'])} observations and risk score "
        f"{result['risk_score']['risk_score_id']} for job {args.job_id}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
