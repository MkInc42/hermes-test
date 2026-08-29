"""CLI entry points for the persistence layer.

    python -m pte migrate     # apply pending migrations
    python -m pte status      # show migration status
"""

from __future__ import annotations

import sys
from pathlib import Path

from .db import DbConfig, apply_migrations, migration_status
from .scanner import create_job_output_dir, run_dry_scan


def main(argv: list[str] | None = None) -> int:
    """Run CLI subcommands; returns process exit code."""
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "migrate"
    if cmd == "scan-dry-run":
        if len(argv) != 3 or argv[1] != "--output-root":
            print("usage: python -m pte scan-dry-run --output-root DIRECTORY", file=sys.stderr)
            return 2
        output = create_job_output_dir(Path(argv[2]).resolve(), "dry-run-proof")
        result = run_dry_scan("https://example.invalid/benign", output)
        print(f"created {len(result.artifacts)} offline artifacts in {output}")
        return 0
    cfg = DbConfig.from_env()
    if cmd == "migrate":
        applied = apply_migrations(cfg)
        if applied:
            print("applied: " + ", ".join(applied))
        else:
            print("schema already up to date")
        return 0
    if cmd == "status":
        for name, done in migration_status(cfg):
            print(f"{'[x]' if done else '[ ]'} {name}")
        return 0
    print(f"unknown command: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
