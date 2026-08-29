"""Fail-closed contract for disposable, network-isolated URL scan workers.

The module deliberately contains no browser automation dependency.  It defines
the boundary a future browser image must satisfy and provides an offline,
deterministic proof runner for development and tests.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import stat
import subprocess
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Sequence
from urllib.parse import SplitResult, urlsplit, urlunsplit

from .artifacts import ArtifactStore
from .db import DbConfig
from .services import (
    ValidationError,
    get_job_bundle,
    persist_scan_completion,
    set_job_state,
)


class ScanPolicyError(ValueError):
    """A target or runtime setting violates scanner safety policy."""


class ScanExecutionError(RuntimeError):
    """A disposable worker failed or exceeded its deadline."""


class RouteMode(str, Enum):
    """Supported worker routing modes."""

    DRY_RUN = "dry-run"
    PIA_SIDECAR = "pia-sidecar"


class DownloadPolicy(str, Enum):
    """Permitted handling for browser-initiated downloads."""

    BLOCK = "blocked"
    HASH_ONLY = "quarantine-metadata-hash-only"


@dataclass(frozen=True)
class DownloadDecision:
    """Byte-free result of applying the scanner's download policy."""

    policy: DownloadPolicy
    sha256: str | None = None
    byte_size: int | None = None

    def as_metadata(self) -> dict[str, object]:
        """Return explicit passive-only metadata suitable for a manifest."""
        return {
            "policy": self.policy.value,
            "sha256": self.sha256,
            "byte_size": self.byte_size,
            "download_bytes_retained": False,
            "forms_submitted": False,
            "credentials_available": False,
            "submit_operations_available": False,
        }


@dataclass(frozen=True)
class ScannerConfig:
    """Typed runtime policy for one disposable scan worker."""

    image: str = "pte-scanner:local"
    route_mode: RouteMode = RouteMode.DRY_RUN
    pia_service: str = "pia-vpn"
    timeout_seconds: float = 60.0
    kill_grace_seconds: float = 2.0
    allowed_non_default_ports: frozenset[int] = frozenset()
    download_policy: DownloadPolicy = DownloadPolicy.BLOCK
    docker_binary: str = "docker"

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0 or self.kill_grace_seconds < 0:
            raise ScanPolicyError("worker timeouts must be positive")
        if not self.image.strip() or not self.pia_service.strip():
            raise ScanPolicyError("container image and PIA service are required")
        if any(port < 1 or port > 65535 for port in self.allowed_non_default_ports):
            raise ScanPolicyError("allowlisted ports must be within 1..65535")


@dataclass(frozen=True)
class ValidatedTarget:
    """Canonical target whose resolved addresses passed policy."""

    url: str
    hostname: str
    port: int
    resolved_addresses: tuple[str, ...]


@dataclass(frozen=True)
class ScanArtifact:
    """One immutable output produced by a worker."""

    filename: str
    derived_kind: str
    media_type: str
    data: bytes

    @property
    def sha256(self) -> str:
        """Return the chain-of-custody digest for exact artifact bytes."""
        return hashlib.sha256(self.data).hexdigest()


@dataclass(frozen=True)
class ScanResult:
    """Complete output and policy provenance for one scan."""

    target_url: str
    route_label: str
    policy: dict[str, object]
    artifacts: tuple[ScanArtifact, ...]
    output_dir: Path


Resolver = Callable[..., Sequence[tuple[object, ...]]]

_SAFE_JOB_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_BLOCKED_HOSTNAMES = frozenset({
    "instance-data", "localhost", "metadata", "metadata.google.internal",
})


def _address_is_blocked(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return whether an address is unsafe for an untrusted browser fetch."""
    cgnat = ipaddress.ip_network("100.64.0.0/10")
    metadata = (ipaddress.ip_network("169.254.169.254/32"),
                ipaddress.ip_network("fd00:ec2::254/128"))
    return (
        not address.is_global
        # WHY: keep the explicit classes visible even though is_global currently
        # covers them; this makes the fail-closed policy resilient and auditable.
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or (address.version == 4 and address in cgnat)
        or any(address in network for network in metadata)
    )


def validate_url(target: str, *, allowed_non_default_ports: frozenset[int] = frozenset(),
                 resolver: Resolver = socket.getaddrinfo) -> ValidatedTarget:
    """Validate and resolve an HTTP(S) target before any fetch occurs.

    All returned DNS answers must be public.  Callers must use the returned
    target immediately inside a network boundary that also prevents private
    egress; DNS can otherwise change between validation and navigation.
    """
    if not isinstance(target, str) or not target or target != target.strip():
        raise ScanPolicyError("target must be a non-empty URL without surrounding whitespace")
    try:
        parsed = urlsplit(target)
        port = parsed.port
    except ValueError as exc:
        raise ScanPolicyError("target contains an invalid or ambiguous authority") from exc
    if parsed.scheme not in {"http", "https"}:
        raise ScanPolicyError("only explicit http:// and https:// targets are allowed")
    if not parsed.netloc or not parsed.hostname:
        raise ScanPolicyError("target requires an unambiguous hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ScanPolicyError("URL userinfo is forbidden")
    hostname = parsed.hostname
    if "%" in hostname or hostname.endswith(".") or any(ch.isspace() for ch in hostname):
        raise ScanPolicyError("encoded, whitespace, and trailing-dot hostnames are forbidden")
    normalized_hostname = hostname.lower()
    if (normalized_hostname in _BLOCKED_HOSTNAMES
            or normalized_hostname.endswith(".localhost")
            or normalized_hostname.endswith(".local")):
        # WHY: names with local/metadata semantics must never reach a resolver;
        # a resolver under attacker or platform control could return a public IP.
        raise ScanPolicyError("local and cloud metadata hostnames are forbidden")
    effective_port = port or (443 if parsed.scheme == "https" else 80)
    if effective_port not in {80, 443} and effective_port not in allowed_non_default_ports:
        raise ScanPolicyError(f"non-default port {effective_port} is not allowlisted")

    try:
        literal = ipaddress.ip_address(hostname)
        addresses = {literal}
    except ValueError:
        try:
            answers = resolver(hostname, effective_port, type=socket.SOCK_STREAM)
            addresses = {ipaddress.ip_address(str(answer[4][0])) for answer in answers}
        except (OSError, ValueError, IndexError) as exc:
            raise ScanPolicyError("target hostname did not resolve safely") from exc
    if not addresses:
        raise ScanPolicyError("target hostname returned no addresses")
    blocked = sorted(str(address) for address in addresses if _address_is_blocked(address))
    if blocked:
        raise ScanPolicyError("target resolves to a blocked address class: " + ", ".join(blocked))
    canonical = urlunsplit(SplitResult(parsed.scheme, parsed.netloc, parsed.path or "/",
                                       parsed.query, ""))
    return ValidatedTarget(canonical, hostname, effective_port,
                           tuple(sorted(str(address) for address in addresses)))


def create_job_output_dir(root: Path, job_id: str | uuid.UUID) -> Path:
    """Create a contained mode-0700 directory for a UUID or safe job name."""
    job_name = str(job_id)
    if not isinstance(job_id, (str, uuid.UUID)) or not _SAFE_JOB_ID.fullmatch(job_name):
        raise ScanPolicyError("job_id must be one conservative path component")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    resolved_root = root.resolve(strict=True)
    if not resolved_root.is_dir():
        raise ScanPolicyError("job output root must be a directory")
    output = resolved_root / job_name
    # resolve(strict=False) follows an already-present symlink, catching escape
    # before mkdir; the post-create check protects the returned contract too.
    candidate = output.resolve(strict=False)
    if not candidate.is_relative_to(resolved_root):
        raise ScanPolicyError("job output directory would escape its root")
    try:
        output.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise ScanPolicyError("job output directory already exists; workers are single-use") from exc
    resolved_output = output.resolve(strict=True)
    if not resolved_output.is_relative_to(resolved_root):
        raise ScanPolicyError("job output directory escaped its root")
    return resolved_output


def handle_download(content: bytes | None = None, *,
                    policy: DownloadPolicy = DownloadPolicy.BLOCK) -> DownloadDecision:
    """Apply a passive download policy without returning or retaining bytes.

    The default blocks before content handling.  HASH_ONLY permits callers to
    provide in-memory bytes solely to calculate size and SHA-256 metadata; the
    returned object deliberately has no byte-bearing field or active operation.
    """
    if policy is DownloadPolicy.BLOCK:
        return DownloadDecision(policy=policy)
    if policy is not DownloadPolicy.HASH_ONLY:
        raise ScanPolicyError("unsupported download policy")
    if not isinstance(content, bytes):
        raise ScanPolicyError("hash-only download handling requires bytes")
    return DownloadDecision(
        policy=policy, sha256=hashlib.sha256(content).hexdigest(), byte_size=len(content)
    )


def build_container_command(config: ScannerConfig, target: ValidatedTarget,
                            output_dir: Path) -> list[str]:
    """Build a hardened, single-use Docker worker invocation."""
    if config.route_mode is not RouteMode.PIA_SIDECAR:
        raise ScanPolicyError("live container jobs require route_mode=pia-sidecar")
    if not output_dir.is_absolute() or not output_dir.is_dir():
        raise ScanPolicyError("an existing absolute per-job output directory is required")
    # WHY: sharing the PIA container network namespace is the Docker CLI
    # equivalent of Compose `network_mode: service:pia-vpn`.
    return [
        config.docker_binary, "run", "--rm", "--read-only", "--user=65532:65532",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true", "--network",
        f"container:{config.pia_service}", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev",
        "--mount", f"type=bind,src={output_dir},dst=/output,rw",
        config.image, "scan", "--target", target.url, "--output", "/output",
        "--fresh-profile", "--disable-forms", "--disable-credentials",
        "--download-policy", config.download_policy.value,
    ]


class DockerRunner:
    """Subprocess adapter with explicit timeout, terminate, and kill behavior."""

    def __init__(self, popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen) -> None:
        self._popen = popen

    def run(self, command: Sequence[str], *, timeout_seconds: float,
            kill_grace_seconds: float) -> None:
        """Run a worker and forcibly kill it if graceful termination fails."""
        try:
            process = self._popen(list(command), stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        except OSError as exc:
            raise ScanExecutionError("scanner worker could not be started") from exc
        try:
            _stdout, stderr = process.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            process.terminate()
            try:
                process.communicate(timeout=kill_grace_seconds)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
            raise ScanExecutionError("scanner worker timed out and was stopped") from exc
        if process.returncode != 0:
            detail = stderr.decode("utf-8", errors="replace")[-1000:]
            raise ScanExecutionError(f"scanner worker exited {process.returncode}: {detail}")


_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M/wHwAF/gL+MxKVWQAAAABJRU5ErkJggg=="
)


def run_dry_scan(target: str, output_dir: Path,
                 download_policy: DownloadPolicy = DownloadPolicy.BLOCK) -> ScanResult:
    """Produce deterministic benign artifacts without DNS or network I/O."""
    parsed = urlsplit(target)
    if target != "https://example.invalid/benign" or parsed.scheme != "https":
        raise ScanPolicyError("dry-run accepts only https://example.invalid/benign")
    if (not output_dir.is_absolute() or output_dir.is_symlink()
            or not output_dir.is_dir() or any(output_dir.iterdir())):
        raise ScanPolicyError("dry-run requires an existing empty absolute job directory")
    policy: dict[str, object] = {
        "network_io": False,
        "route_mode": RouteMode.DRY_RUN.value,
        "url_validation": "fixed-offline-fixture-no-dns",
        "forms_submitted": False,
        "credentials_available": False,
        "browser_profile": "fresh-disposable",
        "downloads": download_policy.value,
        "download_bytes_retained": False,
    }
    raw: list[tuple[str, str, str, bytes]] = [
        ("screenshot.png", "screenshot_capture", "image/png", _PNG),
        ("dom.html", "dom_snapshot", "text/html",
         b"<!doctype html><title>Offline benign fixture</title><p>network disabled</p>\n"),
        ("network.har", "har", "application/json",
         json.dumps({"log": {"version": "1.2", "creator": {"name": "pte-dry-run", "version": "1"},
                             "entries": []}}, sort_keys=True, separators=(",", ":")).encode()),
        ("redirect-chain.json", "redirect_chain", "application/json",
         json.dumps({"initial_url": target, "hops": [], "final_url": target},
                    sort_keys=True, separators=(",", ":")).encode()),
    ]
    manifest_entries = [{"filename": name, "derived_kind": kind, "media_type": media,
                         "sha256": hashlib.sha256(data).hexdigest(), "byte_size": len(data)}
                        for name, kind, media, data in raw]
    manifest = json.dumps({"schema_version": 1, "target_url": target, "result": "ok",
                           "route_label": "direct-dev", "policy": policy,
                           "artifacts": manifest_entries}, sort_keys=True,
                          separators=(",", ":")).encode()
    raw.append(("scan-manifest.json", "enrichment_payload", "application/json", manifest))
    artifacts = tuple(ScanArtifact(*item) for item in raw)
    temporary: list[Path] = []
    published: list[Path] = []
    try:
        for artifact in artifacts:
            path = output_dir / artifact.filename
            temporary_path = output_dir / f".{artifact.filename}.{uuid.uuid4().hex}.tmp"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(temporary_path, flags, 0o600)
            temporary.append(temporary_path)
            with os.fdopen(fd, "wb") as stream:
                stream.write(artifact.data)
                stream.flush()
                os.fsync(stream.fileno())
            if not stat.S_ISREG(temporary_path.lstat().st_mode):
                raise ScanPolicyError("dry-run artifact staging path is not a regular file")
            # Hard-link publication is atomic and refuses to replace a symlink or
            # any other object raced into the final artifact path.
            os.link(temporary_path, path, follow_symlinks=False)
            published.append(path)
            temporary_path.unlink()
            temporary.remove(temporary_path)
    except (OSError, ScanPolicyError):
        for path in (*temporary, *published):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise
    return ScanResult(target, "direct-dev", policy, artifacts, output_dir)


def run_dry_scan_job(
    cfg: DbConfig,
    *,
    tenant_uid: str,
    job_id: uuid.UUID | str,
    submission_id: uuid.UUID | str,
    output_root: Path,
    artifact_store: ArtifactStore | None = None,
    actor: str = "scanner-runner",
) -> dict[str, object]:
    """Run and atomically persist one deterministic, DB-backed scan job.

    The caller supplies every tenant-scoped identifier. The job must already be
    queued. Its single-use output directory is retained for inspection. If scan
    execution or completion persistence fails, the exception propagates and the
    job remains in its last nonterminal state; completion is never recorded
    without all artifact rows, the scan event, and source status.
    """
    job = get_job_bundle(cfg, tenant_uid, job_id)["job"]
    if job["state"] != "queued":
        raise ValidationError("dry scan job requires a queued job")
    if job["submission_id"] != uuid.UUID(str(submission_id)):
        raise ValidationError("dry scan job submission does not match the job")
    output_dir = create_job_output_dir(output_root, job_id)
    for state in ("normalizing", "policy_checked", "scanning"):
        set_job_state(cfg, tenant_uid, job_id, state, actor=actor)
    result = run_dry_scan("https://example.invalid/benign", output_dir)
    store = artifact_store or ArtifactStore()
    completion = persist_scan_completion(
        cfg,
        tenant_uid=tenant_uid,
        job_id=job_id,
        submission_id=submission_id,
        route_label=result.route_label,
        policy=result.policy,
        artifacts=[
            {
                "derived_kind": item.derived_kind,
                "media_type": item.media_type,
                "data": item.data,
            }
            for item in result.artifacts
        ],
        storage_writer=store.put,
        actor=actor,
    )
    return {"result": result, "completion": completion}
