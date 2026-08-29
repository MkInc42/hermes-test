"""Immutable, content-addressed local artifact storage."""

from __future__ import annotations

import os
from pathlib import Path

from .services import compute_sha256


class ArtifactStorageError(Exception):
    """A local artifact could not be safely persisted."""


class ArtifactStore:
    """Write evidence once beneath ``PTE_ARTIFACT_ROOT`` without exposing paths."""

    def __init__(self, root: Path | None = None) -> None:
        """Initialize a local content-addressed store.

        Args:
            root: Storage root, or ``PTE_ARTIFACT_ROOT`` when omitted.
        """
        self.root = root or Path(os.environ.get("PTE_ARTIFACT_ROOT", "./artifacts"))

    def put(self, tenant_uid: str, data: bytes) -> str:
        """Persist an immutable tenant-scoped artifact.

        Args:
            tenant_uid: Tenant owning the artifact.
            data: Exact artifact bytes.

        Returns:
            An opaque relative storage pointer for internal persistence.

        Raises:
            ArtifactStorageError: If storage fails or existing bytes differ.
        """
        digest = compute_sha256(data)
        safe_tenant = compute_sha256(tenant_uid.encode("utf-8"))[:24]
        relative = Path(safe_tenant) / digest[:2] / digest
        target = self.root.resolve() / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            try:
                existing = target.read_bytes()
            except OSError as exc:
                raise ArtifactStorageError("artifact storage unavailable") from exc
            if existing != data:
                raise ArtifactStorageError("artifact storage integrity check failed")
        except OSError as exc:
            raise ArtifactStorageError("artifact storage unavailable") from exc
        else:
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError as exc:
                raise ArtifactStorageError("artifact storage unavailable") from exc
        return relative.as_posix()

    def remove_if_unreferenced(self, pointer: str) -> None:
        """Best-effort rollback cleanup for a content-addressed blob.

        Args:
            pointer: Internal relative pointer previously returned by :meth:`put`.

        Raises:
            ArtifactStorageError: If the pointer resolves outside the storage root.
        """
        root = self.root.resolve()
        target = (root / pointer).resolve()
        if not target.is_relative_to(root):
            raise ArtifactStorageError("artifact pointer is outside storage root")
        try:
            target.unlink()
        except FileNotFoundError:
            pass
