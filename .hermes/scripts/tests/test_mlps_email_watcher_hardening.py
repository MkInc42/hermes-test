"""Compact regression tests for MLPS watcher timeout hardening (t_778eb7d8).

Covers only the two behaviors that matter for this fix:
  1. run_himalaya retries timeouts/transient exits and succeeds on a later attempt.
  2. An exhausted folder query aborts main() with NO state save and NO dispatch.

All subprocess activity is faked; nothing touches the live mailbox or cron.
"""

import importlib.util
import subprocess
from pathlib import Path

import pytest

SCRIPT_PATH = Path("/home/black/.hermes/scripts/mlps-email-watcher.py")
REQUIRED_FOLDERS = ["MLPS: Incoming", "MLPS: Processing",
                    "MLPS: Completed", "MLPS: Awaiting Response", "INBOX"]


def load_watcher():
    """Import the dash-named production script as a module under test."""
    spec = importlib.util.spec_from_file_location("mlps_email_watcher", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def watcher():
    return load_watcher()


def fake_run(monkeypatch, mod, outcomes, calls):
    """Scripted subprocess.run stand-in: each call pops the next outcome."""
    def run(cmd, capture_output=False, text=False, timeout=None):
        calls.append(timeout)
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome
    monkeypatch.setattr(mod.subprocess, "run", run)


# ─── 1. Retry succeeds after transient failures ──────────────────────────────
@pytest.mark.parametrize("first_failure", [
    subprocess.TimeoutExpired(cmd="himalaya", timeout=30),
    type("R", (), {"stdout": "", "stderr": "imap hiccup\n", "returncode": 1})(),
], ids=["timeout-then-retry", "nonzero-then-retry"])
def test_transient_failure_retried_then_success(watcher, monkeypatch, first_failure,
                                                capsys):
    calls = []
    outcomes = [
        first_failure,
        first_failure,
        type("R", (), {"stdout": "[]", "stderr": "", "returncode": 0})(),
    ]
    sleeps = []
    monkeypatch.setattr(watcher.time, "sleep", lambda s: sleeps.append(s))
    fake_run(monkeypatch, watcher, outcomes, calls)

    out = watcher.run_himalaya(["envelope", "list", "--folder", "INBOX"])

    # One 30s initial attempt plus 60s-capped retries, short backoff between.
    assert out == "[]"
    assert calls == [30, 60, 60]
    assert sleeps == [watcher.RETRY_BACKOFF_SECONDS] * 2
    assert capsys.readouterr().err == ""


# ─── 2. Exhausted query: no state save, no dispatch ──────────────────────────
@pytest.mark.parametrize("folder", REQUIRED_FOLDERS)
def test_exhausted_query_no_save_no_dispatch(watcher, monkeypatch, tmp_path,
                                             folder, capsys):
    monkeypatch.setattr(watcher, "STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr(watcher, "load_assistant_ledger", lambda: {})

    real_list_folder = watcher.list_folder

    def failing_list_folder(name, page_size=50):
        # Only the target folder's himalaya attempts time out -> None.
        # Every other folder queries cleanly, proving main() aborts on the
        # first unavailable folder rather than continuing past it.
        if name != folder:
            return []
        outcomes = [subprocess.TimeoutExpired(cmd="himalaya", timeout=30),
                    subprocess.TimeoutExpired(cmd="himalaya", timeout=60),
                    subprocess.TimeoutExpired(cmd="himalaya", timeout=60)]
        calls = []
        fake_run(monkeypatch, watcher, outcomes, calls)
        return real_list_folder(name)

    monkeypatch.setattr(watcher, "list_folder", failing_list_folder)

    saved = []
    dispatched = []
    monkeypatch.setattr(watcher, "save_state", lambda s: saved.append(s))
    monkeypatch.setattr(watcher, "dispatch_assistant",
                        lambda lines: dispatched.append(lines) or 0)

    with pytest.raises(SystemExit) as excinfo:
        watcher.main()

    assert excinfo.value.code != 0
    err = capsys.readouterr().err
    # Exactly one concise folder-specific diagnostic.
    assert len(err.strip().splitlines()) == 1
    assert folder in err
    assert not saved
    assert not dispatched
