"""Focused tests for the dependency-free frontend runtime."""

from __future__ import annotations

from pathlib import Path
import json
import subprocess

import pytest


ROOT = Path(__file__).parents[1]
VALIDATOR = ROOT / "frontend" / "js" / "api-base.js"


def run_validator(value: str) -> subprocess.CompletedProcess[str]:
    script = (
        "const validator = require(process.argv[1]).normalizedApiBase;"
        "try { console.log(validator(JSON.parse(process.argv[2]))); }"
        "catch (error) { console.error(error.message); process.exit(2); }"
    )
    return subprocess.run(
        ["node", "-e", script, str(VALIDATOR), json.dumps(value)],
        check=False,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    ("value", "normalized"),
    [
        ("http://127.0.0.1:8000", "http://127.0.0.1:8000"),
        ("https://localhost:8443/", "https://localhost:8443"),
        ("http://[::1]:8000", "http://[::1]:8000"),
    ],
)
def test_api_base_accepts_only_loopback_origins(value, normalized):
    result = run_validator(value)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == normalized


@pytest.mark.parametrize(
    "value",
    [
        "https://example.test:8000",
        "http://127.0.0.1.example.test:8000",
        "http://user@localhost:8000",
        "http://localhost:8000/path",
        "http://localhost:8000?",
        "http://localhost:8000/?debug=1",
        "http://localhost:8000#",
        "http://localhost:8000/#status",
        "ftp://localhost:8000",
        "not a URL",
    ],
)
def test_api_base_rejects_unsafe_or_non_origin_values(value):
    result = run_validator(value)
    assert result.returncode == 2
