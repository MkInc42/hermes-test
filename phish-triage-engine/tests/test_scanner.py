"""Focused safety and output-contract tests for disposable scan workers."""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from pathlib import Path

import pytest

from pte.artifacts import ArtifactStore
from pte.scanner import (
    DockerRunner,
    DownloadPolicy,
    RouteMode,
    ScanExecutionError,
    ScannerConfig,
    ScanPolicyError,
    build_container_command,
    create_job_output_dir,
    handle_download,
    run_dry_scan,
    run_dry_scan_job,
    validate_url,
)
from pte.services import (
    CrossTenantAccessError,
    create_job,
    create_submission,
    get_job_bundle,
    persist_scan_completion,
    set_job_state,
)


def _resolver_for(*addresses: str):
    return lambda *_args, **_kwargs: [
        (2, 1, 6, "", (address, 0)) for address in addresses
    ]


@pytest.mark.parametrize("target", [
    "ftp://example.test/file", "//example.test/path", "https://u:p@example.test/",
    "https://example.test.:443/", " https://example.test/", "http://example.test:8080/",
])
def test_url_rejects_ambiguous_scheme_authority_and_ports(target):
    with pytest.raises(ScanPolicyError):
        validate_url(target, resolver=_resolver_for("8.8.8.8"))


@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.0.0.1", "169.254.1.2", "224.0.0.1", "192.0.2.1",
    "100.64.0.1", "169.254.169.254", "::1", "fe80::1", "ff02::1",
])
def test_url_rejects_non_public_and_metadata_addresses(address):
    with pytest.raises(ScanPolicyError, match="blocked address"):
        validate_url("https://example.test/", resolver=_resolver_for(address))


def test_url_requires_every_dns_answer_to_be_public_and_allows_explicit_port():
    with pytest.raises(ScanPolicyError):
        validate_url("https://example.test/", resolver=_resolver_for("8.8.8.8", "127.0.0.1"))
    target = validate_url("https://example.test:8443/a#fragment",
                          allowed_non_default_ports=frozenset({8443}),
                          resolver=_resolver_for("8.8.8.8"))
    assert target.url == "https://example.test:8443/a"
    assert target.resolved_addresses == ("8.8.8.8",)


@pytest.mark.parametrize("hostname", [
    "metadata.google.internal", "metadata", "instance-data", "localhost",
    "service.local", "child.localhost",
])
def test_url_rejects_local_and_metadata_names_without_resolving(hostname):
    called = False

    def resolver(*_args, **_kwargs):
        nonlocal called
        called = True
        return _resolver_for("8.8.8.8")()

    with pytest.raises(ScanPolicyError, match="metadata hostnames"):
        validate_url(f"https://{hostname}/", resolver=resolver)
    assert called is False


@pytest.mark.parametrize("address", ["192.0.0.8", "2001:db8::1"])
def test_url_fails_closed_for_addresses_that_are_not_global(address):
    with pytest.raises(ScanPolicyError, match="blocked address"):
        validate_url("https://example.test/", resolver=_resolver_for(address))


@pytest.mark.parametrize("job_id", [
    "../escape", "a/b", "a\\b", "/absolute", ".", "..", ".hidden", "",
])
def test_job_output_rejects_unsafe_path_components(tmp_path, job_id):
    with pytest.raises(ScanPolicyError, match="path component"):
        create_job_output_dir(tmp_path / "jobs", job_id)


def test_job_output_accepts_uuid_and_safe_name_and_blocks_symlink_escape(tmp_path):
    root = tmp_path / "jobs"
    first = create_job_output_dir(root, uuid.uuid4())
    second = create_job_output_dir(root, "job_01.alpha-beta")
    assert first.parent == second.parent == root.resolve()

    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "linked-job").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ScanPolicyError, match="escape"):
        create_job_output_dir(root, "linked-job")


def test_job_output_is_worker_writable_without_world_access(tmp_path):
    worker_uid = os.geteuid()
    worker_gid = os.getegid()
    output = create_job_output_dir(tmp_path / "jobs", "worker-owned",
                                   worker_uid=worker_uid, worker_gid=worker_gid)
    metadata = output.stat()
    assert (metadata.st_uid, metadata.st_gid) == (worker_uid, worker_gid)
    assert metadata.st_mode & 0o777 == 0o700
    assert metadata.st_mode & 0o007 == 0  # unrelated identities get no access
    artifact = output / "artifact.json"
    artifact.write_bytes(b"{}")
    assert artifact.read_bytes() == b"{}"


def test_live_worker_identity_defaults_to_declared_non_root_uid_gid():
    config = ScannerConfig()
    assert (config.worker_uid, config.worker_gid) == (65532, 65532)


@pytest.mark.parametrize("field,value", [
    ("worker_uid", -1), ("worker_gid", -1), ("worker_uid", True),
    ("worker_gid", 2**31),
])
def test_worker_identity_is_explicitly_validated(field, value):
    with pytest.raises(ScanPolicyError, match=field):
        ScannerConfig(**{field: value})


def test_live_route_and_rebinding_boundary_fail_closed(tmp_path):
    output = create_job_output_dir(tmp_path.resolve(), uuid.uuid4())
    target = validate_url("https://example.test/", resolver=_resolver_for("8.8.8.8"))
    with pytest.raises(ScanPolicyError, match="pia-sidecar"):
        build_container_command(ScannerConfig(), target, output)
    # A public preflight answer cannot authorize passing an attacker-controlled
    # hostname to a namespace where its next answer could be 127.0.0.1/private.
    local = ScannerConfig(route_mode=RouteMode.PIA_SIDECAR,
                          worker_uid=os.geteuid(), worker_gid=os.getegid())
    with pytest.raises(ScanPolicyError, match="address-pinned runtime egress"):
        build_container_command(local, target, output)


class _HungProcess:
    returncode = None

    def __init__(self):
        self.calls = 0
        self.terminated = False
        self.killed = False

    def communicate(self, timeout=None):
        self.calls += 1
        if self.calls < 3:
            raise subprocess.TimeoutExpired("scanner", timeout)
        self.returncode = -9
        return b"", b""

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


class _GracefulAfterStopProcess(_HungProcess):
    def communicate(self, timeout=None):
        self.calls += 1
        if self.calls == 1:
            raise subprocess.TimeoutExpired("scanner", timeout)
        self.returncode = 0
        return b"", b""


class _ExitedProcess:
    def __init__(self, returncode=0, stderr=b""):
        self.returncode = returncode
        self.stderr = stderr

    def communicate(self, timeout=None):
        return b"", self.stderr


def _successful_cleanup(command, **_kwargs):
    return subprocess.CompletedProcess(command, 0, b"", b"")


def test_timeout_stops_named_container_gracefully_then_removes():
    process = _GracefulAfterStopProcess()
    cleanup = []
    runner = DockerRunner(lambda *_args, **_kwargs: process,
                          lambda command, **_kwargs: (
                              cleanup.append(command) or _successful_cleanup(command)
                          ))
    with pytest.raises(ScanExecutionError, match="timed out"):
        runner.run(["docker", "run", "--name", "pte-scan-job1", "image"],
                   timeout_seconds=0.01, kill_grace_seconds=2)
    assert cleanup == [
        ["docker", "stop", "--time", "2", "pte-scan-job1"],
        ["docker", "rm", "--force", "pte-scan-job1"],
    ]


def test_timeout_forces_named_container_kill_then_removes():
    process = _HungProcess()
    cleanup = []
    runner = DockerRunner(lambda *_args, **_kwargs: process,
                          lambda command, **_kwargs: (
                              cleanup.append(command) or _successful_cleanup(command)
                          ))
    with pytest.raises(ScanExecutionError, match="timed out"):
        runner.run(["docker", "run", "--name", "pte-scan-job2", "image"],
                   timeout_seconds=0.01, kill_grace_seconds=0.01)
    assert cleanup == [
        ["docker", "stop", "--time", "0", "pte-scan-job2"],
        ["docker", "kill", "pte-scan-job2"],
        ["docker", "rm", "--force", "pte-scan-job2"],
    ]


def test_cleanup_calls_are_bounded_and_failures_do_not_skip_later_stages():
    process = _HungProcess()
    cleanup = []

    def failing_cleanup(command, **kwargs):
        cleanup.append((command, kwargs))
        if command[1] == "stop":
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        if command[1] == "kill":
            raise OSError("docker unavailable")
        return _successful_cleanup(command)

    runner = DockerRunner(lambda *_args, **_kwargs: process, failing_cleanup)
    with pytest.raises(ScanExecutionError, match="cleanup failed"):
        runner.run(["docker", "run", "--name", "pte-scan-job3", "image"],
                   timeout_seconds=0.01, kill_grace_seconds=0.01)

    assert [call[0][1] for call in cleanup] == ["stop", "kill", "rm"]
    assert all(call[1]["timeout"] == 5.0 for call in cleanup)


def test_successful_worker_is_removed_before_success_is_reported():
    cleanup = []

    def cleanup_run(command, **_kwargs):
        cleanup.append(command)
        return _successful_cleanup(command)

    DockerRunner(lambda *_args, **_kwargs: _ExitedProcess(), cleanup_run).run(
        ["docker", "run", "--name", "pte-scan-success", "image"],
        timeout_seconds=1, kill_grace_seconds=0,
    )
    assert cleanup == [["docker", "rm", "--force", "pte-scan-success"]]


def test_nonzero_worker_is_removed_before_worker_failure_is_reported():
    cleanup = []

    def cleanup_run(command, **_kwargs):
        cleanup.append(command)
        return _successful_cleanup(command)

    runner = DockerRunner(
        lambda *_args, **_kwargs: _ExitedProcess(7, b"worker failed"), cleanup_run
    )
    with pytest.raises(ScanExecutionError, match="worker exited 7: worker failed"):
        runner.run(["docker", "run", "--name", "pte-scan-failed", "image"],
                   timeout_seconds=1, kill_grace_seconds=0)
    assert cleanup == [["docker", "rm", "--force", "pte-scan-failed"]]


@pytest.mark.parametrize("cleanup_result", [
    subprocess.CompletedProcess(["docker", "rm"], 1, b"", b"still running"),
    OSError("docker unavailable"),
])
def test_cleanup_failure_overrides_successful_or_nonzero_worker(cleanup_result):
    def cleanup_run(command, **_kwargs):
        if isinstance(cleanup_result, BaseException):
            raise cleanup_result
        return cleanup_result

    for returncode in (0, 7):
        runner = DockerRunner(
            lambda *_args, **_kwargs: _ExitedProcess(returncode, b"worker failed"),
            cleanup_run,
        )
        with pytest.raises(ScanExecutionError, match="cleanup failed") as raised:
            runner.run(["docker", "run", "--name", f"pte-scan-{returncode}", "image"],
                       timeout_seconds=1, kill_grace_seconds=0)
        assert "removed" not in str(raised.value)


def test_runner_requires_named_container_contract():
    with pytest.raises(ScanPolicyError, match="explicit --name"):
        DockerRunner().run(["docker", "run", "image"], timeout_seconds=1,
                           kill_grace_seconds=0)


def test_worker_start_oserror_is_scan_execution_error():
    def unavailable(*_args, **_kwargs):
        raise OSError("docker missing")

    with pytest.raises(ScanExecutionError, match="could not be started"):
        DockerRunner(unavailable).run(
            ["docker", "run", "--name", "pte-scan-start", "image"],
            timeout_seconds=1, kill_grace_seconds=0,
        )


def test_dry_run_output_contract_is_deterministic_and_no_submit(tmp_path):
    output = create_job_output_dir(tmp_path.resolve(), "job-one")
    result = run_dry_scan("https://example.invalid/benign", output,
                          DownloadPolicy.HASH_ONLY)
    assert {item.filename for item in result.artifacts} == {
        "screenshot.png", "dom.html", "network.har", "redirect-chain.json",
        "scan-manifest.json",
    }
    manifest = json.loads((output / "scan-manifest.json").read_bytes())
    assert manifest["policy"]["network_io"] is False
    assert manifest["policy"]["forms_submitted"] is False
    assert manifest["policy"]["credentials_available"] is False
    assert manifest["policy"]["downloads"] == "quarantine-metadata-hash-only"
    assert manifest["policy"]["download_bytes_retained"] is False
    assert len(manifest["artifacts"]) == 4
    assert all((output / item.filename).read_bytes() == item.data for item in result.artifacts)


def test_download_handling_defaults_blocked_and_hash_only_is_byte_free():
    blocked = handle_download(b"ignored by block policy")
    assert blocked.as_metadata() == {
        "policy": "blocked", "sha256": None, "byte_size": None,
        "download_bytes_retained": False, "forms_submitted": False,
        "credentials_available": False, "submit_operations_available": False,
    }

    hashed = handle_download(b"payload", policy=DownloadPolicy.HASH_ONLY)
    metadata = hashed.as_metadata()
    assert metadata["sha256"] == "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5"
    assert metadata["byte_size"] == 7
    assert metadata["submit_operations_available"] is False
    assert not hasattr(hashed, "data") and b"payload" not in metadata.values()


def test_dry_run_rejects_symlink_output_directory(tmp_path):
    real_output = tmp_path / "real"
    real_output.mkdir()
    linked_output = tmp_path / "linked"
    linked_output.symlink_to(real_output, target_is_directory=True)
    with pytest.raises(ScanPolicyError, match="empty absolute job directory"):
        run_dry_scan("https://example.invalid/benign", linked_output)


def test_dry_run_removes_partial_outputs_when_a_write_fails(tmp_path, monkeypatch):
    output = create_job_output_dir(tmp_path.resolve(), "write-failure")
    real_fsync = os.fsync
    calls = 0

    def failing_fsync(fd):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("disk full")
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", failing_fsync)
    with pytest.raises(OSError, match="disk full"):
        run_dry_scan("https://example.invalid/benign", output)
    assert list(output.iterdir()) == []


def _job(db, tenant):
    submission = create_submission(db, tenant, "raw_url", envelope={"url": "offline"})
    job = create_job(db, tenant, submission["submission_id"], "raw_url")
    set_job_state(db, tenant, job["job_id"], "scanning")
    return submission, job


def test_scan_completion_persists_artifact_chain_and_lifecycle(db, tenant_a, tmp_path):
    submission, job = _job(db, tenant_a)
    output = create_job_output_dir(tmp_path.resolve() / "jobs", job["job_id"])
    result = run_dry_scan("https://example.invalid/benign", output)
    store = ArtifactStore(tmp_path / "store")
    saved = persist_scan_completion(
        db, tenant_uid=tenant_a, job_id=job["job_id"],
        submission_id=submission["submission_id"], route_label=result.route_label,
        policy=result.policy,
        artifacts=[{"derived_kind": item.derived_kind, "media_type": item.media_type,
                    "data": item.data} for item in result.artifacts],
        storage_writer=store.put,
    )
    bundle = get_job_bundle(db, tenant_a, job["job_id"])
    assert saved["state"] == bundle["job"]["state"] == "completed"
    assert len(bundle["derived_artifacts"]) == 5
    assert bundle["source_status"][0]["status"] == "scanned"
    assert bundle["scan_events"][0]["detail"]["policy"]["forms_submitted"] is False
    assert all((store.root / row["storage_pointer"]).is_file()
               for row in bundle["derived_artifacts"])


def test_run_dry_scan_job_creates_files_and_persists_completion(
        db, tenant_a, tmp_path):
    submission = create_submission(db, tenant_a, "raw_url", envelope={"url": "offline"})
    job = create_job(db, tenant_a, submission["submission_id"], "raw_url")
    store = ArtifactStore(tmp_path / "store")

    run = run_dry_scan_job(
        db,
        tenant_uid=tenant_a,
        job_id=job["job_id"],
        submission_id=submission["submission_id"],
        output_root=tmp_path / "jobs",
        artifact_store=store,
        actor="integration-scanner",
    )

    output = tmp_path / "jobs" / str(job["job_id"])
    bundle = get_job_bundle(db, tenant_a, job["job_id"])
    assert run["completion"]["state"] == bundle["job"]["state"] == "completed"
    assert {path.name for path in output.iterdir()} == {
        "screenshot.png", "dom.html", "network.har", "redirect-chain.json",
        "scan-manifest.json",
    }
    assert len(bundle["derived_artifacts"]) == 5
    assert len(bundle["scan_events"]) == 1
    assert bundle["source_status"][0]["status"] == "scanned"
    assert all((store.root / row["storage_pointer"]).is_file()
               for row in bundle["derived_artifacts"])


def test_scan_completion_is_tenant_scoped_and_storage_failure_is_safe(
        db, tenant_a, tenant_b):
    submission, job = _job(db, tenant_a)
    artifact = {"derived_kind": "har", "media_type": "application/json", "data": b"{}"}
    with pytest.raises(CrossTenantAccessError):
        persist_scan_completion(
            db, tenant_uid=tenant_b, job_id=job["job_id"],
            submission_id=submission["submission_id"], route_label="direct-dev",
            policy={}, artifacts=[artifact], storage_writer=lambda *_: "pointer",
        )
    with pytest.raises(OSError):
        persist_scan_completion(
            db, tenant_uid=tenant_a, job_id=job["job_id"],
            submission_id=submission["submission_id"], route_label="direct-dev",
            policy={}, artifacts=[artifact],
            storage_writer=lambda *_: (_ for _ in ()).throw(OSError("disk unavailable")),
        )
    bundle = get_job_bundle(db, tenant_a, job["job_id"])
    assert bundle["job"]["state"] == "scanning"
    assert bundle["derived_artifacts"] == []
