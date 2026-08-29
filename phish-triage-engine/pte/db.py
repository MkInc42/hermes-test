"""Database connection handling and schema migrations.

Pure stdlib + psycopg. The migration runner applies .sql files in
lexical order inside a single transaction each, recording applied
migrations in schema_migrations. Idempotent: re-running skips applied files.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import psycopg
from psycopg.rows import dict_row

DEFAULT_MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


@dataclass(frozen=True)
class DbConfig:
    """Connection parameters for the triage Postgres database."""

    host: str
    port: int
    dbname: str
    user: str
    password: str

    @classmethod
    def from_env(cls, prefix: str = "PTE_") -> "DbConfig":
        """Build config from PTE_DB_* environment variables (.env values)."""
        return cls(
            host=os.environ.get(f"{prefix}DB_HOST", "127.0.0.1"),
            port=int(os.environ.get(f"{prefix}DB_PORT", "55432")),
            dbname=os.environ.get(f"{prefix}DB_NAME", "phish_triage"),
            user=os.environ.get(f"{prefix}DB_USER", "pte"),
            password=os.environ.get(f"{prefix}DB_PASSWORD", "pte_local_dev_password_change_me"),
        )

    def conninfo(self, dbname: str | None = None) -> str:
        """psycopg conninfo string; dbname override for admin/test databases."""
        return (
            f"host={self.host} port={self.port} dbname={dbname or self.dbname} "
            f"user={self.user} password={self.password}"
        )


def connect(cfg: DbConfig, dbname: str | None = None) -> psycopg.Connection:
    """Open a connection with dict rows and autocommit off."""
    return psycopg.connect(cfg.conninfo(dbname), row_factory=dict_row)


def _migration_files(migrations_dir: Path) -> list[Path]:
    files = sorted(migrations_dir.glob("*.sql"))
    if not files:
        raise RuntimeError(f"no .sql migrations found in {migrations_dir}")
    return files


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ensure_database(cfg: DbConfig, dbname: str) -> None:
    """Create the target database if it does not exist yet (test bootstrap)."""
    with connect(cfg, dbname="postgres") as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (dbname,))
        if cur.fetchone() is None:
            conn.rollback()
            conn.autocommit = True
            cur.execute('CREATE DATABASE "%s"' % dbname.replace('"', ''))
            conn.autocommit = False


def apply_migrations(cfg: DbConfig, migrations_dir: Path | None = None) -> list[str]:
    """Apply pending migrations in lexical order; returns names applied.

    Each migration runs in its own transaction. Checksums are recorded so an
    edited already-applied migration fails loudly instead of drifting.
    """
    migrations_dir = migrations_dir or DEFAULT_MIGRATIONS_DIR
    applied: list[str] = []
    with connect(cfg) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    migration_name TEXT PRIMARY KEY,
                    checksum       CHAR(64) NOT NULL,
                    applied_at     TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            cur.execute("SELECT migration_name, checksum FROM schema_migrations")
            recorded = {row["migration_name"]: row["checksum"] for row in cur.fetchall()}

            for path in _migration_files(migrations_dir):
                name = path.name
                checksum = _sha256_file(path)
                if name in recorded:
                    if recorded[name] != checksum:
                        raise RuntimeError(
                            f"migration {name} changed after being applied "
                            f"(recorded {recorded[name]}, file {checksum})"
                        )
                    continue
                sql = path.read_text(encoding="utf-8")
                try:
                    cur.execute(sql)
                except psycopg.Error:
                    conn.rollback()
                    raise
                cur.execute(
                    "INSERT INTO schema_migrations (migration_name, checksum) VALUES (%s, %s)",
                    (name, checksum),
                )
                applied.append(name)
        conn.commit()
    return applied


def migration_status(cfg: DbConfig, migrations_dir: Path | None = None) -> Iterable[tuple[str, bool]]:
    """Yield (migration_name, applied) for every migration file."""
    migrations_dir = migrations_dir or DEFAULT_MIGRATIONS_DIR
    with connect(cfg) as conn, conn.cursor() as cur:
        cur.execute("SELECT migration_name FROM schema_migrations")
        done = {row["migration_name"] for row in cur.fetchall()}
        for path in _migration_files(migrations_dir):
            yield path.name, path.name in done
