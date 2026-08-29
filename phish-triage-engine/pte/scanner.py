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
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping, Sequence
from urllib.parse import SplitResult, urlsplit, urlunsplit

from .artifacts import ArtifactStore
from .db import DbConfig
from .services import (
    ValidationError,
    get_job_bundle,
    persist_scan_completion,
    persist_scan_failure,
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


class VpnAuthMode(str, Enum):
    """Supported ways to supply OpenVPN authentication."""

    FILE = "auth-file"
    USERNAME_PASSWORD = "username-password"


class VpnInlineAuth:
    """Write-only credentials that cannot be rendered accidentally."""

    __slots__ = ("__username", "__password")

    def __init__(self, username: str, password: str) -> None:
        if not username or not password:
            raise ScanPolicyError("VPN username and password must both be configured")
        self.__username = username
        self.__password = password

    def __repr__(self) -> str:
        return "VpnInlineAuth(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"

    def apply(self, consumer: Callable[[str, str], object]) -> object:
        """Provide credentials only to an injected stdin/file-descriptor adapter."""
        return consumer(self.__username, self.__password)


@dataclass(frozen=True)
class VpnFileAuth:
    """Reference to a locally protected OpenVPN auth file."""

    path: Path = field(repr=False)

    def __repr__(self) -> str:
        return "VpnFileAuth(<configured>)"


VpnAuth = VpnFileAuth | VpnInlineAuth
PathValidator = Callable[[Path], Path]


def _safe_vpn_file(path: Path) -> Path:
    """Validate file metadata without opening or inspecting file contents."""
    if not path.is_absolute():
        raise ScanPolicyError("VPN file paths must be absolute")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except (OSError, ValueError, RuntimeError):
        raise ScanPolicyError("VPN configuration file is missing or unsafe") from None
    if path != resolved or not stat.S_ISREG(metadata.st_mode):
        raise ScanPolicyError("VPN configuration file must be a canonical regular file")
    permissions = stat.S_IMODE(metadata.st_mode)
    if permissions & 0o077:
        raise ScanPolicyError("VPN configuration file permissions are unsafe")
    return resolved


@dataclass(frozen=True)
class VpnRuntimeConfig:
    """Typed local OpenVPN inputs; credential material is never serialized."""

    ovpn_path: Path
    auth: VpnAuth = field(repr=False)

    def __init__(self, ovpn_path: Path, auth: VpnAuth) -> None:
        object.__setattr__(self, "ovpn_path", ovpn_path)
        object.__setattr__(self, "auth", auth)

    @property
    def auth_mode(self) -> VpnAuthMode:
        return (VpnAuthMode.FILE if isinstance(self.auth, VpnFileAuth)
                else VpnAuthMode.USERNAME_PASSWORD)

    def __repr__(self) -> str:
        return (f"VpnRuntimeConfig(ovpn_path={self.ovpn_path!r}, "
                f"auth_mode={self.auth_mode.value!r}, auth=<redacted>)")

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ, *,
                 validate_file: PathValidator = _safe_vpn_file) -> "VpnRuntimeConfig | None":
        ovpn = environ.get("PTE_VPN_OVPN_PATH", "")
        auth_file = environ.get("PTE_VPN_AUTH_FILE", "")
        username = environ.get("PTE_VPN_USERNAME", "")
        password = environ.get("PTE_VPN_PASSWORD", "")
        if not any((ovpn, auth_file, username, password)):
            return None
        if not ovpn:
            raise ScanPolicyError("VPN OVPN path is required")
        if bool(username) != bool(password):
            raise ScanPolicyError("VPN username and password must both be configured")
        inline_mode = bool(username and password)
        if bool(auth_file) == inline_mode:
            raise ScanPolicyError("configure exactly one VPN authentication mode")
        safe_ovpn = validate_file(Path(ovpn))
        if auth_file:
            auth: VpnAuth = VpnFileAuth(validate_file(Path(auth_file)))
        else:
            auth = VpnInlineAuth(username, password)
        return cls(safe_ovpn, auth)


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
    worker_uid: int = 65532
    worker_gid: int = 65532
    vpn: VpnRuntimeConfig | None = None

    @classmethod
    def from_env(cls, prefix: str = "PTE_SCANNER_", *,
                 environ: Mapping[str, str] = os.environ,
                 vpn_file_validator: PathValidator = _safe_vpn_file) -> "ScannerConfig":
        """Load scanner policy and typed, non-renderable VPN inputs."""
        ports_text = environ.get(f"{prefix}ALLOWED_PORTS", "")
        try:
            ports = frozenset(int(value) for value in ports_text.split(",") if value)
            return cls(
                image=environ.get(f"{prefix}IMAGE", cls.image),
                route_mode=RouteMode(environ.get(f"{prefix}ROUTE_MODE", cls.route_mode)),
                pia_service=environ.get(f"{prefix}PIA_SERVICE", cls.pia_service),
                timeout_seconds=float(environ.get(f"{prefix}TIMEOUT_SECONDS",
                                                     cls.timeout_seconds)),
                kill_grace_seconds=float(environ.get(f"{prefix}KILL_GRACE_SECONDS",
                                                        cls.kill_grace_seconds)),
                allowed_non_default_ports=ports,
                download_policy=DownloadPolicy(environ.get(
                    f"{prefix}DOWNLOAD_POLICY", cls.download_policy
                )),
                docker_binary=environ.get(f"{prefix}DOCKER_BINARY", cls.docker_binary),
                worker_uid=int(environ.get(f"{prefix}WORKER_UID", cls.worker_uid)),
                worker_gid=int(environ.get(f"{prefix}WORKER_GID", cls.worker_gid)),
                vpn=VpnRuntimeConfig.from_env(environ, validate_file=vpn_file_validator),
            )
        except ScanPolicyError:
            raise
        except (TypeError, ValueError) as exc:
            raise ScanPolicyError("invalid scanner environment configuration") from exc

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0 or self.kill_grace_seconds < 0:
            raise ScanPolicyError("worker timeouts must be positive")
        if (not self.image.strip() or not self.pia_service.strip()
                or not self.docker_binary.strip()):
            raise ScanPolicyError("container image, PIA service, and Docker binary are required")
        if any(port < 1 or port > 65535 for port in self.allowed_non_default_ports):
            raise ScanPolicyError("allowlisted ports must be within 1..65535")
        for label, value in (("worker_uid", self.worker_uid), ("worker_gid", self.worker_gid)):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 2**31:
                raise ScanPolicyError(f"{label} must be an integer within 1..2147483647")


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
_DOCKER_CLEANUP_TIMEOUT_SECONDS = 5.0


def container_name(job_id: str | uuid.UUID) -> str:
    """Return a deterministic Docker-safe name unique to a persisted job."""
    try:
        canonical = uuid.UUID(str(job_id)).hex
    except (TypeError, ValueError, AttributeError) as exc:
        raise ScanPolicyError("live scanner job_id must be a UUID") from exc
    return f"pte-scan-{canonical}"


def runtime_contract(config: ScannerConfig, job_id: str | uuid.UUID,
                     output_dir: Path) -> dict[str, object]:
    """Describe the future worker boundary without constructing a live command."""
    if config.route_mode is not RouteMode.PIA_SIDECAR:
        raise ScanPolicyError("operator runtime contract requires route_mode=pia-sidecar")
    if config.vpn is None:
        raise ScanPolicyError("operator runtime contract requires local VPN configuration")
    name = container_name(job_id)
    # container_name performs the public fail-closed UUID validation first.
    canonical_job_id = str(uuid.UUID(hex=name.removeprefix("pte-scan-")))
    if not output_dir.is_absolute() or not output_dir.is_dir():
        raise ScanPolicyError("runtime contract requires an existing absolute output directory")
    try:
        resolved_output = output_dir.resolve(strict=True)
    except OSError as exc:
        raise ScanPolicyError("runtime output directory could not be resolved safely") from exc
    if output_dir != resolved_output or output_dir.name != canonical_job_id:
        raise ScanPolicyError(
            "runtime output must be a canonical, non-symlink directory named for the job UUID"
        )
    metadata = output_dir.stat()
    if ((metadata.st_uid, metadata.st_gid) != (config.worker_uid, config.worker_gid)
            or metadata.st_mode & 0o777 != 0o700):
        raise ScanPolicyError("runtime output must be mode 0700 and owned by worker UID/GID")
    return {
        "schema_version": 1,
        "job_id": canonical_job_id,
        "container_name": name,
        "image": config.image,
        "output_dir": str(output_dir),
        "single_use_output": True,
        "worker_uid": config.worker_uid,
        "worker_gid": config.worker_gid,
        "timeout_seconds": config.timeout_seconds,
        "kill_grace_seconds": config.kill_grace_seconds,
        "cleanup_timeout_seconds": _DOCKER_CLEANUP_TIMEOUT_SECONDS,
        "network_mode": f"service:{config.pia_service}",
        "route_mode": config.route_mode.value,
        "vpn": {
            "configured": True,
            "ovpn_path": str(config.vpn.ovpn_path),
            "auth_mode": config.vpn.auth_mode.value,
        },
        "live_enabled": False,
        "required_before_live": [
            "pinned-public-address-navigation",
            "namespace-private-egress-blocking",
        ],
    }


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


def create_job_output_dir(root: Path, job_id: str | uuid.UUID, *,
                          worker_uid: int | None = None,
                          worker_gid: int | None = None) -> Path:
    """Create a contained mode-0700 directory owned by the worker identity."""
    if (worker_uid is None) != (worker_gid is None):
        raise ScanPolicyError("worker_uid and worker_gid must be configured together")
    if worker_uid is None:
        worker_uid, worker_gid = os.geteuid(), os.getegid()
    for label, value in (("worker_uid", worker_uid), ("worker_gid", worker_gid)):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**31:
            raise ScanPolicyError(f"{label} must be an integer within 0..2147483647")
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
    try:
        os.chown(resolved_output, worker_uid, worker_gid)
        os.chmod(resolved_output, 0o700)
    except OSError:
        # Do not return a directory that the configured container identity may
        # be unable to use, or weaken permissions as a workaround.
        try:
            resolved_output.rmdir()
        except OSError:
            pass
        raise
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
    """Refuse live construction until address-pinned egress exists.

    PIA namespace sharing remains the intended route, but it is not itself an
    egress security boundary: navigating the original hostname would permit a
    second DNS answer to rebind the browser to a private address.
    """
    if config.route_mode is not RouteMode.PIA_SIDECAR:
        raise ScanPolicyError("live container jobs require route_mode=pia-sidecar")
    if not output_dir.is_absolute() or not output_dir.is_dir():
        raise ScanPolicyError("an existing absolute per-job output directory is required")
    try:
        resolved_output = output_dir.resolve(strict=True)
    except OSError as exc:
        raise ScanPolicyError("job output directory could not be resolved safely") from exc
    if output_dir != resolved_output:
        raise ScanPolicyError("job output directory must be canonical and contain no symlinks")
    metadata = output_dir.stat()
    if ((metadata.st_uid, metadata.st_gid) != (config.worker_uid, config.worker_gid)
            or metadata.st_mode & 0o777 != 0o700):
        raise ScanPolicyError("job output must be mode 0700 and owned by the worker UID/GID")
    raise ScanPolicyError(
        "live container command construction is disabled until a fail-closed "
        "address-pinned runtime egress control is implemented"
    )


class DockerRunner:
    """Subprocess adapter that cleans up the actual named Docker container."""

    def __init__(self, popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
                 cleanup_run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run
                 ) -> None:
        self._popen = popen
        self._cleanup_run = cleanup_run

    @staticmethod
    def _container_contract(command: Sequence[str]) -> tuple[str, str]:
        command = list(command)
        try:
            run_index = command.index("run")
            name_index = command.index("--name", run_index + 1)
            name = command[name_index + 1]
        except (ValueError, IndexError) as exc:
            raise ScanPolicyError("Docker worker command requires an explicit --name") from exc
        if not _SAFE_JOB_ID.fullmatch(name):
            raise ScanPolicyError("Docker worker container name is unsafe")
        return command[0], name

    def _docker_cleanup(self, docker: str, name: str, action: str,
                        *arguments: str) -> str | None:
        command = [docker, action, *arguments, name]
        try:
            completed = self._cleanup_run(
                command, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False,
                timeout=_DOCKER_CLEANUP_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return f"docker {action} timed out"
        except OSError as exc:
            return f"docker {action} could not run: {exc}"
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace")[-1000:]
            return f"docker {action} exited {completed.returncode}: {detail}"
        return None

    @staticmethod
    def _raise_cleanup_failure(failures: Sequence[str]) -> None:
        if failures:
            raise ScanExecutionError("scanner worker cleanup failed: " + "; ".join(failures))

    def run(self, command: Sequence[str], *, timeout_seconds: float,
            kill_grace_seconds: float) -> None:
        """Run a worker and forcibly kill it if graceful termination fails."""
        docker, container_name = self._container_contract(command)
        try:
            process = self._popen(list(command), stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        except OSError as exc:
            raise ScanExecutionError("scanner worker could not be started") from exc
        try:
            _stdout, stderr = process.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            cleanup_failures: list[str] = []
            grace = str(max(0, int(kill_grace_seconds)))
            failure = self._docker_cleanup(docker, container_name, "stop", "--time", grace)
            if failure is not None:
                cleanup_failures.append(failure)
            try:
                process.communicate(timeout=kill_grace_seconds)
            except subprocess.TimeoutExpired:
                failure = self._docker_cleanup(docker, container_name, "kill")
                if failure is not None:
                    cleanup_failures.append(failure)
                try:
                    process.communicate(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()  # reap a wedged CLI after container cleanup
                    process.communicate()
            finally:
                failure = self._docker_cleanup(docker, container_name, "rm", "--force")
                if failure is not None:
                    cleanup_failures.append(failure)
            if cleanup_failures:
                try:
                    self._raise_cleanup_failure(cleanup_failures)
                except ScanExecutionError as cleanup_exc:
                    raise cleanup_exc from exc
            raise ScanExecutionError("scanner worker timed out") from exc
        cleanup_failure = self._docker_cleanup(docker, container_name, "rm", "--force")
        self._raise_cleanup_failure([cleanup_failure] if cleanup_failure is not None else [])
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
    try:
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
    except Exception as exc:
        status = "blocked" if isinstance(exc, ScanPolicyError) else "failed"
        reason = "scanner_policy_blocked" if status == "blocked" else "scanner_execution_failed"
        try:
            persist_scan_failure(
                cfg, tenant_uid=tenant_uid, job_id=job_id,
                submission_id=submission_id, status=status, reason_code=reason,
                route_label="blocked-no-route" if status == "blocked" else "direct-dev",
                actor=actor,
            )
        except Exception as persistence_exc:
            exc.add_note(f"scanner failure persistence also failed: {type(persistence_exc).__name__}")
        raise
    return {"result": result, "completion": completion}
