"""Project-owned polling worker for tenant-scoped queued triage jobs."""

from __future__ import annotations

import argparse
import math
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import psycopg

from .adapters import unavailable_provider_results
from .artifacts import ArtifactStore, ArtifactStorageError
from .db import DbConfig
from .enrichment import build_enrichment_contract, persist_enrichment_job, utc_observed_at
from .reports import defang_indicator
from .scanner import (RouteMode, ScanResult, ScannerConfig, create_job_output_dir,
                      run_dry_scan, run_live_scan)
from .services import (
    PersistenceError, ValidationError, add_indicators, claim_queued_job,
    get_job_bundle, persist_report_bundle, persist_scan_completion,
    record_job_failure, requeue_terminal_job, set_job_state,
)

WORKER_ACTOR = "pipeline-worker"
DRY_SCAN_PROOF_URL = "https://example.invalid/benign"
DRY_SCAN_ROUTE_LABEL = "direct-dev"
WORKER_MODES = frozenset({"offline", "vpn-live"})


def _non_negative_finite_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(parsed) or parsed < 0:
        raise argparse.ArgumentTypeError("must be finite and non-negative")
    return parsed


def _non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


@dataclass(frozen=True)
class WorkerConfig:
    tenant_uid: str
    poll_interval: float = 2.0
    max_jobs: int = 0
    once: bool = False
    dry_scan: bool = True
    mode: str = "offline"
    output_root: Path = Path("./tmp/pipeline-jobs")

    def __post_init__(self) -> None:
        if not math.isfinite(self.poll_interval) or self.poll_interval < 0:
            raise ValueError("poll interval must be a finite non-negative number")
        if self.max_jobs < 0:
            raise ValueError("max jobs must be non-negative")
        if self.mode not in WORKER_MODES:
            raise ValueError("worker mode must be offline or vpn-live")
        if self.mode == "offline" and not self.dry_scan:
            raise ValueError("offline mode requires the fixed dry scan proof")
        if self.mode == "vpn-live" and self.dry_scan:
            raise ValueError("vpn-live mode cannot use the offline dry scan")

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ) -> "WorkerConfig":
        return cls(
            tenant_uid=environ.get("PTE_WORKER_TENANT_UID", ""),
            poll_interval=float(environ.get("PTE_WORKER_POLL_INTERVAL", "2")),
            max_jobs=int(environ.get("PTE_WORKER_MAX_JOBS", "0")),
            once=environ.get("PTE_WORKER_ONCE", "").lower() in {"1", "true", "yes"},
            dry_scan=environ.get("PTE_WORKER_DRY_SCAN", "true").lower() in {"1", "true", "yes"},
            mode=environ.get("PTE_WORKER_MODE", "offline"),
            output_root=Path(environ.get("PTE_WORKER_OUTPUT_ROOT", "./tmp/pipeline-jobs")),
        )


def _target_url(bundle: dict[str, Any]) -> str:
    for indicator in bundle["indicators"]:
        if indicator["indicator_type"] == "url" and indicator["raw_value"]:
            return str(indicator["raw_value"])
    raise ValidationError("missing persisted URL indicator")


def _ensure_url_indicators(cfg: DbConfig, tenant_uid: str, job_id: Any,
                           target_url: str) -> None:
    """Idempotently persist the URL hostname when strict parsing permits it."""
    from urllib.parse import urlsplit
    hostname = urlsplit(target_url).hostname
    if not hostname:
        return
    add_indicators(cfg, tenant_uid, job_id, [{
        "indicator_type": "domain", "raw_value": hostname,
        "defanged_value": defang_indicator("domain", hostname),
        "provenance": "parsed",
    }])


def _verify_offline_dry_scan(scan: ScanResult) -> None:
    """Fail closed unless the scanner attests to the fixed offline proof."""
    if (scan.target_url != DRY_SCAN_PROOF_URL
            or scan.route_label != DRY_SCAN_ROUTE_LABEL
            or scan.policy.get("network_io") is not False
            or scan.policy.get("route_mode") != "dry-run"):
        raise ValidationError("dry scan did not return the required offline policy evidence")


def process_claimed_job(cfg: DbConfig, *, job: dict[str, Any], config: WorkerConfig,
                        artifact_store: ArtifactStore | None = None) -> dict[str, Any]:
    """Consume one already-claimed job through scan, enrichment, and reports."""
    tenant_uid, job_id = job["tenant_uid"], job["job_id"]
    store = artifact_store or ArtifactStore()
    bundle = get_job_bundle(cfg, tenant_uid, job_id)
    target_url = _target_url(bundle)

    scan_result = None
    if config.mode == "offline" and config.dry_scan:
        output = create_job_output_dir(config.output_root.resolve(), job_id)
        set_job_state(cfg, tenant_uid, job_id, "policy_checked", actor=WORKER_ACTOR)
        set_job_state(cfg, tenant_uid, job_id, "scanning", actor=WORKER_ACTOR)
        # This constant is deliberately unrelated to the submitted indicator.
        # The safe queue worker has no live scan/navigation/network-probe path.
        scan = run_dry_scan(DRY_SCAN_PROOF_URL, output)
        _verify_offline_dry_scan(scan)
        scan_result = persist_scan_completion(
            cfg, tenant_uid=tenant_uid, job_id=job_id,
            submission_id=job["submission_id"], route_label=scan.route_label,
            policy=scan.policy,
            artifacts=[{"derived_kind": item.derived_kind, "media_type": item.media_type,
                        "data": item.data} for item in scan.artifacts],
            storage_writer=store.put, actor=WORKER_ACTOR, completion_state="analyzing",
        )
    elif config.mode == "vpn-live":
        scanner_config = ScannerConfig.from_env()
        if scanner_config.route_mode is not RouteMode.PIA_SIDECAR:
            raise ValidationError("vpn-live jobs require route_mode=pia-sidecar")
        output = create_job_output_dir(
            config.output_root.resolve(), job_id, worker_uid=scanner_config.worker_uid,
            worker_gid=scanner_config.worker_gid,
        )
        set_job_state(cfg, tenant_uid, job_id, "policy_checked", actor=WORKER_ACTOR)
        set_job_state(cfg, tenant_uid, job_id, "scanning", actor=WORKER_ACTOR)
        scan = run_live_scan(target_url, output, job_id=job_id, config=scanner_config)
        scan_result = persist_scan_completion(
            cfg, tenant_uid=tenant_uid, job_id=job_id,
            submission_id=job["submission_id"], route_label=scan.route_label,
            policy=scan.policy,
            artifacts=[{"derived_kind": item.derived_kind, "media_type": item.media_type,
                        "data": item.data} for item in scan.artifacts],
            storage_writer=store.put, actor=WORKER_ACTOR, completion_state="analyzing",
        )

    # Submitted URLs are used only by deterministic local analysis. In dry-scan
    # mode, do not derive or persist anything from them until the scanner's
    # offline route/policy evidence has passed the fail-closed check above.
    _ensure_url_indicators(cfg, tenant_uid, job_id, target_url)

    contract = build_enrichment_contract(
        target_url=target_url, source_type=job["source_type"],
        provider_results=unavailable_provider_results(target_url),
        observed_at=utc_observed_at(),
    )
    enrichment = persist_enrichment_job(
        cfg, tenant_uid=tenant_uid, job_id=job_id, contract=contract,
        artifact_store=store, actor=WORKER_ACTOR, completion_state="analyzing",
    )
    report = persist_report_bundle(
        cfg, tenant_uid=tenant_uid, job_id=job_id,
        storage_writer=store.put, actor=WORKER_ACTOR,
    )
    return {"job_id": str(job_id), "scan": scan_result, "enrichment": enrichment,
            "report": report}


def consume_one(cfg: DbConfig, *, config: WorkerConfig,
                artifact_store: ArtifactStore | None = None) -> dict[str, Any] | None:
    job = claim_queued_job(cfg, tenant_uid=config.tenant_uid, actor=WORKER_ACTOR)
    if job is None:
        return None
    try:
        return process_claimed_job(cfg, job=job, config=config, artifact_store=artifact_store)
    except ValidationError:
        record_job_failure(cfg, tenant_uid=config.tenant_uid, job_id=job["job_id"],
                           status="blocked", reason_code="insufficient_safe_input")
    except (ArtifactStorageError, OSError):
        record_job_failure(cfg, tenant_uid=config.tenant_uid, job_id=job["job_id"],
                           status="failed", reason_code="local_artifact_failure")
    except Exception:
        record_job_failure(cfg, tenant_uid=config.tenant_uid, job_id=job["job_id"],
                           status="failed", reason_code="pipeline_execution_failed")
    return {"job_id": str(job["job_id"]), "state": "terminal_failure"}


def run_worker(cfg: DbConfig, *, config: WorkerConfig,
               artifact_store: ArtifactStore | None = None) -> int:
    if not config.tenant_uid:
        raise ValueError("tenant UID is required")
    consumed = 0
    while config.max_jobs == 0 or consumed < config.max_jobs:
        result = consume_one(cfg, config=config, artifact_store=artifact_store)
        if result is not None:
            consumed += 1
        if config.once:
            break
        if result is None:
            time.sleep(config.poll_interval)
    return consumed


def main(argv: list[str] | None = None) -> int:
    try:
        defaults = WorkerConfig.from_env()
    except ValueError:
        print("pipeline worker configuration is invalid", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant-uid", default=defaults.tenant_uid, required=not defaults.tenant_uid)
    parser.add_argument("--poll-interval", type=_non_negative_finite_float,
                        default=defaults.poll_interval)
    parser.add_argument("--max-jobs", type=_non_negative_int, default=defaults.max_jobs)
    parser.add_argument("--once", action="store_true", default=defaults.once)
    parser.add_argument("--no-dry-scan", action="store_true", help="skip the fixed offline scan proof")
    parser.add_argument("--mode", choices=sorted(WORKER_MODES), default=defaults.mode)
    parser.add_argument("--output-root", type=Path, default=defaults.output_root)
    parser.add_argument("--retry-job-id", help="requeue one failed/blocked job and exit")
    args = parser.parse_args(argv)
    cfg = DbConfig.from_env()
    try:
        if args.retry_job_id:
            requeue_terminal_job(cfg, tenant_uid=args.tenant_uid, job_id=args.retry_job_id)
            print(f"requeued job {args.retry_job_id}")
            return 0
        count = run_worker(cfg, config=WorkerConfig(
            tenant_uid=args.tenant_uid, poll_interval=args.poll_interval,
            max_jobs=args.max_jobs, once=args.once,
            dry_scan=(defaults.dry_scan and not args.no_dry_scan
                      and args.mode == "offline"), mode=args.mode,
            output_root=args.output_root,
        ))
    except (psycopg.Error, PersistenceError, ValueError, OSError):
        print("pipeline worker failed safely; inspect redacted audit events", file=sys.stderr)
        return 1
    print(f"consumed {count} queued job(s) for tenant {args.tenant_uid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
