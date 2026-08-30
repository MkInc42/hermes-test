"""Container entrypoint compatibility and scanner-image contract tests."""

import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _convert(tmp_path: Path, content: str):
    source = tmp_path / "fixture.ovpn"
    runtime = tmp_path / "runtime.ovpn"
    source.write_text(content)
    source.chmod(0o400)
    completed = subprocess.run([
        "sh", str(ROOT / "docker/vpn-sidecar/prepare-config.sh"),
        str(source), str(runtime),
    ], capture_output=True, text=True, check=False)
    return source, runtime, completed


def test_legacy_compression_is_converted_in_runtime_copy_only(tmp_path):
    original = "client\nscramble obfuscate\ncompress\ncomp-lzo no\nremote vpn.example 1198 udp\n"
    source, runtime, completed = _convert(tmp_path, original)
    assert completed.returncode == 0
    assert completed.stdout == completed.stderr == ""
    assert source.read_text() == original
    converted = runtime.read_text()
    assert "\ncompress\n" not in converted and "comp-lzo" not in converted
    assert "scramble" not in converted
    assert converted.count("allow-compression asym") == 1
    assert runtime.stat().st_mode & 0o777 == 0o600


def test_profile_without_legacy_compression_explicitly_disables_it(tmp_path):
    _source, runtime, completed = _convert(tmp_path, "client\nremote vpn.example\n")
    assert completed.returncode == 0
    assert runtime.read_text().endswith("allow-compression no\n")


def test_remote_literal_is_pinned_in_ephemeral_profile(tmp_path):
    profile = tmp_path / "runtime.ovpn"
    profile.write_text("client\nremote 192.0.2.10 1198 udp\n")
    completed = subprocess.run([
        "sh", str(ROOT / "docker/vpn-sidecar/pin-remotes.sh"), str(profile),
    ], capture_output=True, text=True, check=False)
    assert completed.returncode == 0
    assert completed.stdout == completed.stderr == ""
    assert profile.read_text() == "client\nremote 192.0.2.10 1198 udp\n"
    assert profile.stat().st_mode & 0o777 == 0o600


def test_outbound_compression_request_fails_without_profile_disclosure(tmp_path):
    secret_marker = "never-render-this-value"
    source, runtime, completed = _convert(
        tmp_path, f"client\n# {secret_marker}\nallow-compression yes\n")
    assert completed.returncode != 0
    assert not runtime.exists()
    assert secret_marker not in completed.stdout + completed.stderr
    assert source.read_text().endswith("allow-compression yes\n")


def test_scanner_image_declares_non_root_contract_and_redacted_failure(tmp_path):
    dockerfile = (ROOT / "docker/scanner/Dockerfile").read_text()
    assert "USER 65532:65532" in dockerfile
    target = tmp_path / "target"
    output = tmp_path / "output"
    output.mkdir()
    target.write_text("file:///secret-token")
    completed = subprocess.run([
        "python3", str(ROOT / "docker/scanner/scanner.py"), "scan",
        "--target-file", str(target), "--output", str(output),
    ], capture_output=True, text=True, check=False)
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == "scanner failed safely\n"
    assert "secret-token" not in completed.stderr
