"""Focused queue-consumer and pipeline lifecycle tests."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from pte.artifacts import ArtifactStore
from pte.db import connect
from pte import pipeline_worker
from pte.pipeline_worker import WorkerConfig, consume_one
from pte.services import (
    add_indicators, claim_queued_job, create_job, create_submission,
    get_job_bundle, requeue_terminal_job,
)


def _queued(db, tenant_uid: str, *, with_url: bool = True):
    submission = create_submission(db, tenant_uid, "raw_url", envelope={"mode": "test"})
    job = create_job(db, tenant_uid, submission["submission_id"], "raw_url")
    if with_url:
        add_indicators(db, tenant_uid, job["job_id"], [{
            "indicator_type": "url", "raw_value": "https://example.test/path?token=secret",
            "defanged_value": "hxxps://example[.]test/path",
        }])
    return job


def test_claim_is_tenant_scoped_and_consumes_queue_once(db, tenant_a, tenant_b):
    expected = _queued(db, tenant_a)
    _queued(db, tenant_b)
    claimed = claim_queued_job(db, tenant_uid=tenant_a, actor="test-worker")
    assert claimed and claimed["job_id"] == expected["job_id"]
    assert claimed["state"] == "normalizing"
    assert claim_queued_job(db, tenant_uid=tenant_a, actor="test-worker") is None
    assert claim_queued_job(db, tenant_uid=tenant_b, actor="test-worker") is not None


def test_concurrent_claim_does_not_double_process(db, tenant_a):
    expected = _queued(db, tenant_a)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(
            lambda _: claim_queued_job(db, tenant_uid=tenant_a, actor="test-worker"),
            range(2),
        ))
    claimed = [row for row in results if row is not None]
    assert len(claimed) == 1 and claimed[0]["job_id"] == expected["job_id"]


def test_worker_persists_scan_enrichment_report_and_artifacts(db, tenant_a, tmp_path):
    job = _queued(db, tenant_a)
    result = consume_one(
        db,
        config=WorkerConfig(tenant_uid=tenant_a, once=True,
                            output_root=tmp_path / "runs"),
        artifact_store=ArtifactStore(tmp_path / "store"),
    )
    assert result and result["job_id"] == str(job["job_id"])
    bundle = get_job_bundle(db, tenant_a, job["job_id"])
    assert bundle["job"]["state"] == "completed"
    assert bundle["risk_scores"] and len(bundle["reports"]) == 1
    assert sum(row["derived_kind"] == "report_file"
               for row in bundle["derived_artifacts"]) == 2
    assert any(row["indicator_type"] == "domain" for row in bundle["indicators"])
    assert len(bundle["scan_events"]) == 1
    evidence = bundle["scan_events"][0]
    assert evidence["route_label"] == "direct-dev"
    assert evidence["detail"]["policy"]["network_io"] is False
    assert evidence["detail"]["policy"]["route_mode"] == "dry-run"


def test_worker_scanner_only_receives_fixed_offline_proof(db, tenant_a, tmp_path,
                                                          monkeypatch):
    job = _queued(db, tenant_a)
    submitted_url = "https://example.test/path?token=secret"
    calls = []
    real_run_dry_scan = pipeline_worker.run_dry_scan

    def observe_target(target, output):
        calls.append(target)
        assert target != submitted_url
        return real_run_dry_scan(target, output)

    monkeypatch.setattr(pipeline_worker, "run_dry_scan", observe_target)
    consume_one(
        db,
        config=WorkerConfig(tenant_uid=tenant_a, once=True,
                            output_root=tmp_path / "runs"),
        artifact_store=ArtifactStore(tmp_path / "store"),
    )
    assert calls == [pipeline_worker.DRY_SCAN_PROOF_URL]
    assert get_job_bundle(db, tenant_a, job["job_id"])["job"]["state"] == "completed"


@pytest.mark.parametrize("policy_update", [
    {"network_io": True},
    {"network_io": None},
    {"route_mode": "pia-sidecar"},
    {"route_mode": None},
])
def test_worker_rejects_dry_scan_policy_before_persisting_results(
        db, tenant_a, tmp_path, monkeypatch, policy_update):
    job = _queued(db, tenant_a)
    real_run_dry_scan = pipeline_worker.run_dry_scan

    def return_untrusted_policy(target, output):
        result = real_run_dry_scan(target, output)
        return replace(result, policy={**result.policy, **policy_update})

    def forbidden(*args, **kwargs):
        raise AssertionError("unverified scan result was persisted")

    monkeypatch.setattr(pipeline_worker, "run_dry_scan", return_untrusted_policy)
    monkeypatch.setattr(pipeline_worker, "persist_scan_completion", forbidden)
    monkeypatch.setattr(pipeline_worker, "_ensure_url_indicators", forbidden)

    result = consume_one(
        db,
        config=WorkerConfig(tenant_uid=tenant_a, once=True,
                            output_root=tmp_path / "runs"),
        artifact_store=ArtifactStore(tmp_path / "store"),
    )
    assert result == {"job_id": str(job["job_id"]), "state": "terminal_failure"}
    bundle = get_job_bundle(db, tenant_a, job["job_id"])
    assert bundle["job"]["state"] == "blocked"
    assert bundle["scan_events"] == []
    assert bundle["derived_artifacts"] == []


def test_report_persistence_failure_records_failed_job_without_report(db, tenant_a, tmp_path,
                                                                      monkeypatch):
    job = _queued(db, tenant_a)

    def fail_report(*args, **kwargs):
        raise RuntimeError("sensitive report failure detail")

    monkeypatch.setattr(pipeline_worker, "persist_report_bundle", fail_report)
    result = consume_one(
        db,
        config=WorkerConfig(tenant_uid=tenant_a, once=True,
                            output_root=tmp_path / "runs"),
        artifact_store=ArtifactStore(tmp_path / "store"),
    )

    assert result == {"job_id": str(job["job_id"]), "state": "terminal_failure"}
    bundle = get_job_bundle(db, tenant_a, job["job_id"])
    assert bundle["job"]["state"] == "failed"
    assert bundle["reports"] == []
    with connect(db) as conn, conn.cursor() as cur:
        cur.execute("SELECT detail FROM audit_events WHERE tenant_uid=%s AND job_id=%s"
                    " AND action='job_state:failed'", (tenant_a, job["job_id"]))
        detail = cur.fetchone()["detail"]
    assert detail["reason_code"] == "pipeline_execution_failed"
    assert "sensitive report failure detail" not in str(detail)


@pytest.mark.parametrize("poll_interval", [-0.01, float("nan"), float("inf")])
def test_worker_config_rejects_invalid_poll_interval(poll_interval):
    with pytest.raises(ValueError, match="poll interval"):
        WorkerConfig(tenant_uid="cust_TEST", poll_interval=poll_interval)


def test_worker_config_rejects_negative_max_jobs():
    with pytest.raises(ValueError, match="max jobs"):
        WorkerConfig(tenant_uid="cust_TEST", max_jobs=-1)


@pytest.mark.parametrize("name,value", [
    ("PTE_WORKER_POLL_INTERVAL", "soon"),
    ("PTE_WORKER_MAX_JOBS", "many"),
])
def test_worker_config_rejects_malformed_env_numeric(name, value):
    with pytest.raises(ValueError):
        WorkerConfig.from_env({"PTE_WORKER_TENANT_UID": "cust_TEST", name: value})


@pytest.mark.parametrize("option,value", [
    ("--poll-interval", "-0.1"),
    ("--poll-interval", "nan"),
    ("--max-jobs", "-1"),
    ("--max-jobs", "many"),
])
def test_worker_cli_rejects_invalid_numeric_controls(option, value, monkeypatch):
    monkeypatch.setattr(WorkerConfig, "from_env", classmethod(lambda cls: cls(tenant_uid="")))
    with pytest.raises(SystemExit) as exc_info:
        pipeline_worker.main(["--tenant-uid", "cust_TEST", option, value])
    assert exc_info.value.code == 2


def test_missing_safe_indicator_blocks_with_redacted_audit_and_explicit_retry(db, tenant_a,
                                                                              tmp_path):
    job = _queued(db, tenant_a, with_url=False)
    result = consume_one(
        db,
        config=WorkerConfig(tenant_uid=tenant_a, once=True,
                            output_root=tmp_path / "runs"),
        artifact_store=ArtifactStore(tmp_path / "store"),
    )
    assert result and result["state"] == "terminal_failure"
    assert get_job_bundle(db, tenant_a, job["job_id"])["job"]["state"] == "blocked"
    with connect(db) as conn, conn.cursor() as cur:
        cur.execute("SELECT detail FROM audit_events WHERE tenant_uid=%s AND job_id=%s"
                    " AND action='job_state:blocked'", (tenant_a, job["job_id"]))
        detail = cur.fetchone()["detail"]
    assert detail == {"reason_code": "insufficient_safe_input",
                      "terminal_status": "blocked", "retryable": True}
    assert requeue_terminal_job(db, tenant_uid=tenant_a,
                                job_id=job["job_id"])["state"] == "queued"
