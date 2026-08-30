"""Focused tests for the dependency-free frontend runtime."""

from __future__ import annotations

from pathlib import Path
import json
import subprocess

import pytest


ROOT = Path(__file__).parents[1]
VALIDATOR = ROOT / "frontend" / "js" / "api-base.js"


def run_validator(value: str, page_url: str = "http://127.0.0.1:8080") -> subprocess.CompletedProcess[str]:
    script = (
        "const validator = require(process.argv[1]).normalizedApiBase;"
        "try { console.log(validator(JSON.parse(process.argv[2]), new URL(process.argv[3]))); }"
        "catch (error) { console.error(error.message); process.exit(2); }"
    )
    return subprocess.run(
        ["node", "-e", script, str(VALIDATOR), json.dumps(value), page_url],
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


def run_default(page_url: str) -> str:
    script = (
        "const derive = require(process.argv[1]).defaultApiBase;"
        "console.log(derive(new URL(process.argv[2])));"
    )
    result = subprocess.run(["node", "-e", script, str(VALIDATOR), page_url], check=True,
                            capture_output=True, text=True)
    return result.stdout.strip()


@pytest.mark.parametrize(
    ("page_url", "expected"),
    [
        ("http://127.0.0.1:8080/", "http://127.0.0.1:8000"),
        ("http://localhost:8080/", "http://localhost:8000"),
        ("http://[::1]:8080/", "http://[::1]:8000"),
        ("http://192.168.1.115:8088/", "http://192.168.1.115:8012"),
        ("https://triage.lan:8088/", "https://triage.lan:8012"),
    ],
)
def test_api_base_derives_from_page_location(page_url, expected):
    assert run_default(page_url) == expected


def test_api_base_accepts_same_page_host_for_lan():
    result = run_validator("http://192.168.1.115:8012", "http://192.168.1.115:8088")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "http://192.168.1.115:8012"


@pytest.mark.parametrize("value", ["http://192.168.1.116:8012", "https://example.test:8012"])
def test_api_base_rejects_host_unrelated_to_lan_page(value):
    assert run_validator(value, "http://192.168.1.115:8088").returncode == 2
