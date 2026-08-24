#!/usr/bin/env python3
"""Validate the runtime dependencies and persistent audit directory."""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
from pathlib import Path


REQUIRED_MODULES = (
    "yaml",
    "jinja2",
    "requests",
    "bs4",
    "lxml",
    "playwright",
    "aiohttp",
    "dns",
)


def main() -> int:
    """Return zero when the container has everything needed to run an audit."""
    failures: list[str] = []

    missing_modules = [
        module_name
        for module_name in REQUIRED_MODULES
        if importlib.util.find_spec(module_name) is None
    ]
    if missing_modules:
        failures.append(f"missing Python modules: {', '.join(missing_modules)}")

    if shutil.which("screamingfrogseospider") is None:
        failures.append("screamingfrogseospider executable is not installed")

    output_directory = Path(os.environ.get("AUDIT_OUTPUT_DIR", "/data/audits"))
    if not output_directory.is_dir():
        failures.append(f"audit output directory is unavailable: {output_directory}")
    else:
        probe_path = output_directory / ".healthcheck"
        try:
            probe_path.write_text("ok\n", encoding="utf-8")
            probe_path.unlink()
        except OSError as error:
            failures.append(f"audit output directory is not writable: {error}")

    if failures:
        print("unhealthy: " + "; ".join(failures), file=sys.stderr)
        return 1

    print("healthy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
