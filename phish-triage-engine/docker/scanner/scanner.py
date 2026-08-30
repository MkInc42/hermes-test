#!/usr/bin/python3
"""Minimal passive Chromium runtime for the disposable scanner contract."""

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import urllib.parse

APPROVED = ("screenshot.png", "dom.html", "network.har", "redirect-chain.json")
CHROMIUM_HOME = pathlib.Path("/tmp/pte-chromium-home")


def atomic_write(path: pathlib.Path, data: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def scan(target_file: pathlib.Path, output: pathlib.Path) -> int:
    if target_file.is_symlink() or not target_file.is_file():
        raise ValueError("invalid target handoff")
    target = target_file.read_text(encoding="utf-8")
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.fragment:
        raise ValueError("invalid target")
    if output.is_symlink() or not output.is_dir() or any(output.iterdir()):
        raise ValueError("output must be an empty directory")

    screenshot = output / "screenshot.png"
    CHROMIUM_HOME.mkdir(mode=0o700)
    command = [
        "/usr/bin/chromium-browser", "--headless", "--disable-gpu", "--no-sandbox",
        "--disable-dev-shm-usage", "--disable-breakpad", "--disable-crash-reporter",
        "--disable-background-networking",
        "--disable-component-update", "--disable-default-apps", "--disable-extensions",
        "--disable-sync", "--metrics-recording-only", "--no-first-run",
        "--safebrowsing-disable-auto-update", "--disable-features=Translate",
        f"--user-data-dir={CHROMIUM_HOME / 'profile'}",
        f"--disk-cache-dir={CHROMIUM_HOME / 'cache'}",
        "--window-size=1280,960", "--timeout=15000", f"--screenshot={screenshot}",
        "--dump-dom", target,
    ]
    browser_env = {
        "HOME": str(CHROMIUM_HOME),
        "TMPDIR": "/tmp",
        "XDG_CACHE_HOME": str(CHROMIUM_HOME / "cache"),
        "XDG_CONFIG_HOME": str(CHROMIUM_HOME / "config"),
    }
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               timeout=30, check=False, env=browser_env)
    if completed.returncode != 0 or not screenshot.is_file() or not completed.stdout:
        raise RuntimeError("browser capture failed")
    os.chmod(screenshot, 0o600)
    atomic_write(output / "dom.html", completed.stdout)
    atomic_write(output / "network.har", json.dumps({
        "log": {"version": "1.2", "creator": {"name": "pte-scanner", "version": "1"},
                "entries": []}, "capture_note": "passive browser capture; request bodies omitted",
    }, sort_keys=True, separators=(",", ":")).encode())
    atomic_write(output / "redirect-chain.json", json.dumps({
        "initial_url_sha256": hashlib.sha256(target.encode()).hexdigest(),
        "final_url_recording": "omitted", "redirects": [],
    }, sort_keys=True, separators=(",", ":")).encode())
    artifacts = []
    for name in APPROVED:
        data = (output / name).read_bytes()
        artifacts.append({"filename": name, "byte_size": len(data),
                          "sha256": hashlib.sha256(data).hexdigest()})
    atomic_write(output / "scan-manifest.json", json.dumps({
        "schema_version": 1, "route_mode": "pia-sidecar", "network_io": True,
        "browser_profile": "fresh-disposable", "forms_submitted": False,
        "credentials_available": False, "downloads": "blocked",
        "download_bytes_retained": False, "target_url_sha256": hashlib.sha256(
            target.encode()).hexdigest(), "artifacts": artifacts,
    }, sort_keys=True, separators=(",", ":")).encode())
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    command = subparsers.add_parser("scan")
    command.add_argument("--target-file", type=pathlib.Path, required=True)
    command.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        return scan(args.target_file, args.output)
    except Exception:
        print("scanner failed safely", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
