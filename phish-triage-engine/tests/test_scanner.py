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
    container_name,
    create_job_output_dir,
    handle_download,
    run_dry_scan,
    run_dry_scan_job,
    runtime_contract,
    require_vpn_ready,
    run_live_scan,
    VpnReadiness,
    validate_url,
    VpnAuthMode,
    VpnRuntimeConfig,
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


def _vpn_config(tmp_path: Path) -> VpnRuntimeConfig:
    ovpn = tmp_path / "operator.ovpn"
    auth = tmp_path / "operator.auth"
    ovpn.write_text("local test configuration")
    auth.write_text("local test authentication")
    ovpn.chmod(0o600)
    auth.chmod(0o600)
    config = VpnRuntimeConfig.from_env({
        "PTE_VPN_OVPN_PATH": str(ovpn.resolve()),
        "PTE_VPN_AUTH_FILE": str(auth.resolve()),
    })
    assert config is not None
    return config


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
        build_container_command(ScannerConfig(), target, output, output / "target")
    # A public preflight answer cannot authorize passing an attacker-controlled
    # hostname to a namespace where its next answer could be 127.0.0.1/private.
    local = ScannerConfig(route_mode=RouteMode.PIA_SIDECAR,
                          worker_uid=os.geteuid(), worker_gid=os.getegid(),
                          vpn=_vpn_config(tmp_path))
    target_file = tmp_path / "target-url"
    target_file.write_text("https://example.test/")
    target_file.chmod(0o600)
    command = build_container_command(local, target, output, target_file,
                                      job_id=uuid.uuid4())
    assert ["--network", "container:pia-vpn"] == command[
        command.index("--network"):command.index("--network") + 2]
    assert "--read-only" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert command[command.index("--security-opt") + 1] == "no-new-privileges"
    assert command[command.index("--tmpfs") + 1].startswith("/tmp:rw,noexec,nosuid,nodev,")
    assert not any(option in command for option in ("-p", "--publish", "--privileged"))
    assert "example.test:8.8.8.8" in command


def test_live_scan_hands_query_token_through_read_only_target_file(tmp_path):
    job_id = uuid.uuid4()
    output = create_job_output_dir(tmp_path.resolve(), job_id,
                                   worker_uid=os.geteuid(), worker_gid=os.getegid())
    config = ScannerConfig(route_mode=RouteMode.PIA_SIDECAR,
                           worker_uid=os.geteuid(), worker_gid=os.getegid(),
                           vpn=_vpn_config(tmp_path))
    target_url = "https://example.test/path?token=synthetic-regression-token"
    commands = []

    class Runner:
        def run(self, command, **_kwargs):
            commands.append(list(command))
            (output / "scan-manifest.json").write_bytes(b"{}")

    run_live_scan(target_url, output, job_id=job_id, config=config, runner=Runner(),
                  readiness=lambda: VpnReadiness("tun0", "8.8.8.8"),
                  resolver=_resolver_for("8.8.8.8"))
    command = commands[0]
    rendered = " ".join(command)
    assert target_url not in rendered
    assert "synthetic-regression-token" not in rendered
    assert "--target" not in command
    assert command[command.index("--target-file") + 1] == "/run/pte/target-url"
    mounts = [command[index + 1] for index, value in enumerate(command) if value == "--mount"]
    target_mount = next(mount for mount in mounts if "dst=/run/pte/target-url" in mount)
    assert target_mount.endswith(",readonly")
    assert not (tmp_path / f".pte-target-{job_id.hex}").exists()


def test_live_scan_removes_target_file_when_worker_fails(tmp_path):
    job_id = uuid.uuid4()
    output = create_job_output_dir(tmp_path.resolve(), job_id,
                                   worker_uid=os.geteuid(), worker_gid=os.getegid())
    config = ScannerConfig(route_mode=RouteMode.PIA_SIDECAR,
                           worker_uid=os.geteuid(), worker_gid=os.getegid(),
                           vpn=_vpn_config(tmp_path))

    class FailingRunner:
        def run(self, _command, **_kwargs):
            raise ScanExecutionError("synthetic worker failure")

    with pytest.raises(ScanExecutionError, match="synthetic worker failure"):
        run_live_scan("https://example.test/path?token=synthetic", output,
                      job_id=job_id, config=config, runner=FailingRunner(),
                      readiness=lambda: VpnReadiness("tun0", "8.8.8.8"),
                      resolver=_resolver_for("8.8.8.8"))
    assert not (tmp_path / f".pte-target-{job_id.hex}").exists()


def test_operator_runtime_contract_is_deterministic_non_executing_and_pia_scoped(tmp_path):
    job_id = uuid.UUID("00000000-0000-4000-8000-000000000001")
    config = ScannerConfig(
        route_mode=RouteMode.PIA_SIDECAR,
        worker_uid=os.geteuid(), worker_gid=os.getegid(),
        timeout_seconds=12, kill_grace_seconds=3,
        vpn=_vpn_config(tmp_path),
    )
    output = create_job_output_dir(
        tmp_path.resolve(), job_id, worker_uid=os.geteuid(), worker_gid=os.getegid()
    )
    contract = runtime_contract(config, job_id, output)
    assert contract["container_name"] == container_name(job_id)
    assert contract["container_name"] == "pte-scan-00000000000040008000000000000001"
    assert contract["network_mode"] == "service:pia-vpn"
    assert contract["live_enabled"] is True
    assert contract["single_use_output"] is True
    assert contract["cleanup_timeout_seconds"] == 5.0
    assert contract["required_before_live"] == [
        "tunnel-interface-and-default-route", "public-external-egress-identity",
        "pinned-public-address-navigation", "sidecar-firewall-private-egress-blocking",
    ]
    assert contract["vpn"] == {
        "configured": True,
        "ovpn_path": str(config.vpn.ovpn_path),
        "auth_mode": "auth-file",
    }


def test_runtime_contract_rejects_wrong_job_directory_and_symlinked_path(tmp_path):
    job_id = uuid.uuid4()
    config = ScannerConfig(route_mode=RouteMode.PIA_SIDECAR,
                           worker_uid=os.geteuid(), worker_gid=os.getegid(),
                           vpn=_vpn_config(tmp_path))
    wrong = create_job_output_dir(tmp_path.resolve(), uuid.uuid4())
    with pytest.raises(ScanPolicyError, match="named for the job UUID"):
        runtime_contract(config, job_id, wrong)

    real_root = tmp_path / "real"
    output = create_job_output_dir(real_root.resolve(), job_id)
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(real_root, target_is_directory=True)
    with pytest.raises(ScanPolicyError, match="non-symlink"):
        runtime_contract(config, job_id, linked_root / str(job_id))
    assert output.is_dir()


def test_scanner_environment_contract_contains_no_credentials(monkeypatch):
    monkeypatch.setenv("PTE_SCANNER_ROUTE_MODE", "pia-sidecar")
    monkeypatch.setenv("PTE_SCANNER_PIA_SERVICE", "operator-pia")
    monkeypatch.setenv("PTE_SCANNER_ALLOWED_PORTS", "8443,9443")
    monkeypatch.setenv("PTE_SCANNER_DOWNLOAD_POLICY", "quarantine-metadata-hash-only")
    monkeypatch.setenv("PTE_SCANNER_DOCKER_BINARY", "/usr/bin/docker")
    config = ScannerConfig.from_env()
    assert config.pia_service == "operator-pia"
    assert config.allowed_non_default_ports == frozenset({8443, 9443})
    assert config.download_policy is DownloadPolicy.HASH_ONLY
    assert config.docker_binary == "/usr/bin/docker"
    assert not any("password" in field or "credential" in field
                   for field in config.__dataclass_fields__)


def test_vpn_env_parsing_supports_exclusive_auth_modes_without_rendering_secrets(tmp_path):
    ovpn = tmp_path / "safe.ovpn"
    auth_file = tmp_path / "safe.auth"
    ovpn.write_text("fixture only")
    auth_file.write_text("fixture only")
    ovpn.chmod(0o600)
    auth_file.chmod(0o600)

    file_config = ScannerConfig.from_env(environ={
        "PTE_VPN_OVPN_PATH": str(ovpn.resolve()),
        "PTE_VPN_AUTH_FILE": str(auth_file.resolve()),
    })
    assert file_config.vpn is not None
    assert file_config.vpn.auth_mode is VpnAuthMode.FILE

    inline_config = ScannerConfig.from_env(environ={
        "PTE_VPN_OVPN_PATH": str(ovpn.resolve()),
        "PTE_VPN_USERNAME": "test-user-value",
        "PTE_VPN_PASSWORD": "test-password-value",
    })
    rendered = repr(inline_config)
    assert inline_config.vpn is not None
    assert inline_config.vpn.auth_mode is VpnAuthMode.USERNAME_PASSWORD
    assert "test-user-value" not in rendered
    assert "test-password-value" not in rendered
    assert "redacted" in rendered


@pytest.mark.parametrize("env", [
    {"PTE_VPN_OVPN_PATH": "/unused"},
    {"PTE_VPN_OVPN_PATH": "/unused", "PTE_VPN_USERNAME": "user"},
    {"PTE_VPN_OVPN_PATH": "/unused", "PTE_VPN_PASSWORD": "pass"},
    {"PTE_VPN_OVPN_PATH": "/unused", "PTE_VPN_AUTH_FILE": "/auth",
     "PTE_VPN_USERNAME": "user", "PTE_VPN_PASSWORD": "pass"},
    {"PTE_VPN_AUTH_FILE": "/auth"},
])
def test_vpn_env_rejects_missing_or_ambiguous_auth_before_file_access(env):
    def reject_file_access(_path):
        raise AssertionError("invalid authentication configuration accessed a VPN file")

    with pytest.raises(ScanPolicyError):
        ScannerConfig.from_env(environ=env, vpn_file_validator=reject_file_access)


def test_vpn_paths_reject_missing_symlink_directory_and_unsafe_auth_permissions(tmp_path):
    ovpn = tmp_path / "safe.ovpn"
    ovpn.write_text("fixture only")
    ovpn.chmod(0o600)
    safe_env = {"PTE_VPN_OVPN_PATH": str(ovpn.resolve()),
                "PTE_VPN_USERNAME": "user", "PTE_VPN_PASSWORD": "pass"}

    for unsafe in (tmp_path / "missing.ovpn", tmp_path):
        with pytest.raises(ScanPolicyError, match="missing or unsafe|regular file"):
            ScannerConfig.from_env(environ={**safe_env, "PTE_VPN_OVPN_PATH": str(unsafe)})
    linked = tmp_path / "linked.ovpn"
    linked.symlink_to(ovpn)
    with pytest.raises(ScanPolicyError, match="canonical regular file"):
        ScannerConfig.from_env(environ={**safe_env, "PTE_VPN_OVPN_PATH": str(linked)})

    auth = tmp_path / "unsafe.auth"
    auth.write_text("fixture only")
    auth.chmod(0o644)
    with pytest.raises(ScanPolicyError, match="permissions"):
        ScannerConfig.from_env(environ={
            "PTE_VPN_OVPN_PATH": str(ovpn.resolve()),
            "PTE_VPN_AUTH_FILE": str(auth.resolve()),
        })


@pytest.mark.parametrize("metadata_error", [
    ValueError("sensitive path detail"),
    RuntimeError("sensitive path detail"),
])
def test_vpn_path_metadata_errors_are_generic_and_suppress_details(
        tmp_path, monkeypatch, metadata_error):
    ovpn = tmp_path / "operator.ovpn"
    ovpn.write_text("fixture only")
    ovpn.chmod(0o600)
    monkeypatch.setattr(Path, "lstat", lambda _path: (_ for _ in ()).throw(metadata_error))

    with pytest.raises(ScanPolicyError) as raised:
        ScannerConfig.from_env(environ={
            "PTE_VPN_OVPN_PATH": str(ovpn.resolve()),
            "PTE_VPN_USERNAME": "user",
            "PTE_VPN_PASSWORD": "pass",
        })

    assert str(raised.value) == "VPN configuration file is missing or unsafe"
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__ is True


@pytest.mark.parametrize("mode", [0o640, 0o620, 0o604, 0o602])
def test_vpn_paths_reject_any_group_or_other_ovpn_permissions(tmp_path, mode):
    ovpn = tmp_path / "unsafe-permissions.ovpn"
    ovpn.write_text("fixture only")
    ovpn.chmod(mode)

    with pytest.raises(ScanPolicyError, match="permissions"):
        ScannerConfig.from_env(environ={
            "PTE_VPN_OVPN_PATH": str(ovpn.resolve()),
            "PTE_VPN_USERNAME": "user",
            "PTE_VPN_PASSWORD": "pass",
        })


def test_runtime_contract_requires_vpn(tmp_path):
    job_id = uuid.uuid4()
    output = create_job_output_dir(tmp_path.resolve(), job_id)
    config = ScannerConfig(route_mode=RouteMode.PIA_SIDECAR,
                           worker_uid=os.geteuid(), worker_gid=os.getegid())
    with pytest.raises(ScanPolicyError, match="requires local VPN"):
        runtime_contract(config, job_id, output)


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
    with pytest.raises(ScanExecutionError, match="worker exited 7$") as raised:
        runner.run(["docker", "run", "--name", "pte-scan-failed", "image"],
                   timeout_seconds=1, kill_grace_seconds=0)
    assert cleanup == [["docker", "rm", "--force", "pte-scan-failed"]]
    assert "worker failed" not in str(raised.value)


def test_vpn_readiness_is_ordered_and_fail_closed_without_direct_fallback():
    calls = []

    def command(command, timeout):
        calls.append(tuple(command))
        return subprocess.CompletedProcess(command, 1, b"", b"credential=value")

    with pytest.raises(ScanPolicyError, match="readiness") as raised:
        require_vpn_ready(command_adapter=command,
                          command_prefix=("docker", "exec", "pia-vpn"))
    assert calls == [("docker", "exec", "pia-vpn", "test", "-d",
                      "/sys/class/net/tun0")]
    assert "credential" not in str(raised.value)


def test_live_scan_readiness_precedes_target_dns_and_worker(tmp_path):
    output = create_job_output_dir(tmp_path.resolve(), uuid.uuid4(),
                                   worker_uid=os.geteuid(), worker_gid=os.getegid())
    config = ScannerConfig(route_mode=RouteMode.PIA_SIDECAR,
                           worker_uid=os.geteuid(), worker_gid=os.getegid(),
                           vpn=_vpn_config(tmp_path))
    order = []

    def readiness():
        order.append("readiness")
        raise ScanPolicyError("VPN readiness check failed")

    def resolver(*_args, **_kwargs):
        order.append("dns")
        return _resolver_for("8.8.8.8")()

    with pytest.raises(ScanPolicyError):
        run_live_scan("https://example.test/", output, job_id=uuid.uuid4(),
                      config=config, readiness=readiness, resolver=resolver)
    assert order == ["readiness"]


def test_readiness_accepts_tunnel_route_then_public_egress():
    calls = []

    def command(command, _timeout):
        calls.append(command[0])
        if command[0] == "ip":
            stdout = b"1.1.1.1 via 10.0.0.1 dev tun0 src 10.0.0.2\n"
        elif command[0] == "vpn-egress-check":
            stdout = b"8.8.8.8"
        else:
            stdout = b""
        return subprocess.CompletedProcess(command, 0, stdout, b"")

    proof = require_vpn_ready(command_adapter=command)
    assert proof == VpnReadiness("tun0", "8.8.8.8")
    assert calls == ["test", "ip", "vpn-egress-check"]


def test_compose_vpn_profile_has_project_sidecar_and_no_socket_or_scanner_port():
    compose = (Path(__file__).parents[1] / "docker-compose.yml").read_text()
    assert "context: ./docker/vpn-sidecar" in compose
    assert "/var/run/docker.sock" not in compose
    assert "command: ['-f', '']" not in compose
    assert "scanner-worker:" not in compose
    entrypoint = (Path(__file__).parents[1] /
                  "docker/vpn-sidecar/entrypoint.sh").read_text()
    assert "iptables -P OUTPUT DROP" in entrypoint
    assert "ip6tables -P OUTPUT DROP" in entrypoint
    for network in ("10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
                    "172.16.0.0/12", "192.168.0.0/16"):
        assert network in entrypoint


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


def test_dry_scan_job_policy_failure_records_blocked_without_completion(
        db, tenant_a, tmp_path):
    submission = create_submission(db, tenant_a, "raw_url", envelope={"url": "offline"})
    job = create_job(db, tenant_a, submission["submission_id"], "raw_url")
    (tmp_path / "jobs" / str(job["job_id"])).mkdir(parents=True)

    with pytest.raises(ScanPolicyError, match="single-use"):
        run_dry_scan_job(
            db, tenant_uid=tenant_a, job_id=job["job_id"],
            submission_id=submission["submission_id"], output_root=tmp_path / "jobs",
        )

    bundle = get_job_bundle(db, tenant_a, job["job_id"])
    assert bundle["job"]["state"] == "blocked"
    assert bundle["source_status"][0]["status"] == "blocked"
    assert bundle["scan_events"][0]["outcome"] == "blocked"
    assert bundle["derived_artifacts"] == []


def test_dry_scan_job_storage_failure_records_failed_without_completion(
        db, tenant_a, tmp_path):
    submission = create_submission(db, tenant_a, "raw_url", envelope={"url": "offline"})
    job = create_job(db, tenant_a, submission["submission_id"], "raw_url")

    class _UnavailableStore:
        @staticmethod
        def put(*_args):
            raise OSError("storage unavailable")

    with pytest.raises(OSError, match="storage unavailable"):
        run_dry_scan_job(
            db, tenant_uid=tenant_a, job_id=job["job_id"],
            submission_id=submission["submission_id"], output_root=tmp_path / "jobs",
            artifact_store=_UnavailableStore(),
        )

    bundle = get_job_bundle(db, tenant_a, job["job_id"])
    assert bundle["job"]["state"] == "failed"
    assert bundle["source_status"][0]["status"] == "failed"
    assert bundle["scan_events"][0]["outcome"] == "error"
    assert bundle["derived_artifacts"] == []


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
