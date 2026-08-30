"""Container entrypoint compatibility and scanner-image contract tests."""

import importlib.util
import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _load_scanner_runtime():
    path = ROOT / "docker/scanner/scanner.py"
    spec = importlib.util.spec_from_file_location("scanner_runtime", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
    original = "client\nscramble obfuscate provider-mask\ncompress\ncomp-lzo no\nremote vpn.example 1198 udp\n"
    source, runtime, completed = _convert(tmp_path, original)
    assert completed.returncode == 0
    assert completed.stdout == completed.stderr == ""
    assert source.read_text() == original
    converted = runtime.read_text()
    assert "\ncompress\n" not in converted and "comp-lzo" not in converted
    assert "scramble obfuscate provider-mask" in converted
    assert converted.count("allow-compression asym") == 1
    assert runtime.stat().st_mode & 0o777 == 0o600


def test_profile_without_legacy_compression_explicitly_disables_it(tmp_path):
    _source, runtime, completed = _convert(tmp_path, "client\nremote vpn.example\n")
    assert completed.returncode == 0
    assert runtime.read_text().endswith("allow-compression no\n")


def test_remote_literal_is_pinned_in_ephemeral_profile(tmp_path):
    profile = tmp_path / "runtime.ovpn"
    profile.write_text("client\nremote 8.8.8.8 1198 udp\n")
    completed = subprocess.run([
        "sh", str(ROOT / "docker/vpn-sidecar/pin-remotes.sh"), str(profile),
    ], capture_output=True, text=True, check=False)
    assert completed.returncode == 0
    assert completed.stdout == completed.stderr == ""
    assert profile.read_text() == "client\nremote 8.8.8.8 1198 udp\n"
    assert profile.stat().st_mode & 0o777 == 0o600


def test_outbound_compression_request_fails_without_profile_disclosure(tmp_path):
    secret_marker = "never-render-this-value"
    source, runtime, completed = _convert(
        tmp_path, f"client\n# {secret_marker}\nallow-compression yes\n")
    assert completed.returncode != 0
    assert not runtime.exists()
    assert secret_marker not in completed.stdout + completed.stderr
    assert source.read_text().endswith("allow-compression yes\n")


def test_unsupported_scramble_profile_fails_closed_without_disclosure(tmp_path):
    secret_marker = "never-render-this-scramble-value"
    source, runtime, completed = _convert(
        tmp_path, f"client\n# {secret_marker}\nscramble reverse\n")
    assert completed.returncode != 0
    assert not runtime.exists()
    assert completed.stdout == ""
    assert completed.stderr == "VPN profile compatibility conversion failed\n"
    assert secret_marker not in completed.stdout + completed.stderr
    assert source.read_text().endswith("scramble reverse\n")


def test_sidecar_build_pins_reviewable_xor_client():
    dockerfile = (ROOT / "docker/vpn-sidecar/Dockerfile").read_text()
    assert "OPENVPN_VERSION=2.6.22" in dockerfile
    assert "OPENVPN_SHA256=f46df740" in dockerfile
    assert "TUNNELBLICK_COMMIT=c9c73dca6c99" in dockerfile
    assert "tunnelblick-openvpn_xorpatch" in dockerfile
    assert "COPY --from=openvpn-build /stage/usr/sbin/openvpn" in dockerfile


def test_vpn_namespace_owns_explicit_public_resolvers():
    compose = (ROOT / "docker-compose.yml").read_text()
    resolver_file = (ROOT / "docker/vpn-sidecar/resolv.conf").read_text()
    assert "./docker/vpn-sidecar/resolv.conf:/etc/resolv.conf:ro" in compose
    assert "PTE_VPN_DNS_RESOLVERS: 1.1.1.1 1.0.0.1" in compose
    assert resolver_file == "nameserver 1.1.1.1\nnameserver 1.0.0.1\n"
    assert "127.0.0.11" not in resolver_file


def test_sidecar_dns_firewall_contract_is_fail_closed():
    entrypoint = (ROOT / "docker/vpn-sidecar/entrypoint.sh").read_text()
    tunnel_up = (ROOT / "docker/vpn-sidecar/up.sh").read_text()
    drop_at = entrypoint.index("iptables -P OUTPUT DROP")
    dns_at = entrypoint.index("--dport 53")
    pin_at = entrypoint.index('vpn-pin-remotes "$RUNTIME_OVPN"')
    remote_at = entrypoint.index('awk \'$1 == "remote"')
    assert drop_at < dns_at < pin_at < remote_at
    assert '1.1.1.1|1.0.0.1' in entrypoint
    assert '-o eth0 -d "$resolver"' in entrypoint
    assert "iptables -F OUTPUT" in tunnel_up
    assert "iptables -A OUTPUT -o tun0 -j ACCEPT" in tunnel_up
    assert "--dport 53" not in tunnel_up


def test_remote_pinning_uses_only_configured_dns_and_rejects_private_literals(tmp_path):
    script = (ROOT / "docker/vpn-sidecar/pin-remotes.sh").read_text()
    assert '"@$resolver" "$host" A' in script
    assert "getent" not in script
    profile = tmp_path / "runtime.ovpn"
    profile.write_text("client\nremote 192.168.1.1 1198 udp\n")
    completed = subprocess.run([
        "sh", str(ROOT / "docker/vpn-sidecar/pin-remotes.sh"), str(profile),
    ], capture_output=True, text=True, check=False)
    assert completed.returncode != 0
    assert completed.stdout == completed.stderr == ""


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


def test_scanner_gives_chromium_a_writable_disposable_home(tmp_path, monkeypatch):
    runtime = _load_scanner_runtime()
    target = tmp_path / "target"
    output = tmp_path / "output"
    output.mkdir()
    target.write_text("https://example.com/")
    chromium_home = tmp_path / "chromium-home"
    monkeypatch.setattr(runtime, "CHROMIUM_HOME", chromium_home)

    def run(command, **kwargs):
        assert kwargs["env"] == {
            "HOME": str(chromium_home),
            "TMPDIR": "/tmp",
            "XDG_CACHE_HOME": str(chromium_home / "cache"),
            "XDG_CONFIG_HOME": str(chromium_home / "config"),
        }
        assert f"--user-data-dir={chromium_home / 'profile'}" in command
        assert f"--disk-cache-dir={chromium_home / 'cache'}" in command
        assert "--disable-breakpad" in command
        assert "--disable-crash-reporter" in command
        screenshot_arg = next(value for value in command if value.startswith("--screenshot="))
        Path(screenshot_arg.removeprefix("--screenshot=")).write_bytes(b"png")
        return subprocess.CompletedProcess(command, 0, stdout=b"<html></html>")

    monkeypatch.setattr(runtime.subprocess, "run", run)
    assert runtime.scan(target, output) == 0
    assert chromium_home.stat().st_mode & 0o777 == 0o700
    manifest = json.loads((output / "scan-manifest.json").read_text())
    assert manifest["forms_submitted"] is False
    assert manifest["credentials_available"] is False
    assert manifest["downloads"] == "blocked"
