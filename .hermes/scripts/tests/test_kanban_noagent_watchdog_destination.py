"""Focused tests for kanban watchdog Discord destination + report format
standardization (task t_5ea3b79e).

Covers the five required behaviors from the task brief:
  1. Default Discord destination is `1541801982707114004` when no override is
     configured (no env var, no per-board config value).
  2. Blocked report includes the board ID/slug line (`Board ID: <slug>`).
  3. All-done report includes the board ID/slug line.
  4. Ordinary in-progress state (running/todo/ready mix, none done) emits NO
     report at all.
  5. Existing active_task_ids filtering behavior and state-default robustness
     (missing/corrupt state file falls back to clean defaults) do not regress.

Everything external is faked: `hermes kanban ls` output is injected by
monkeypatching run(), Discord posting is captured (never sent), and the state
file lives in a tmp directory. No real network traffic, no cron changes.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT_PATH = Path("/home/black/.hermes/scripts/kanban-noagent-watchdog.py")
EXPECTED_DEFAULT_CHANNEL = "1541801982707114004"


def load_watchdog():
    """Import the dash-named production script as a module under test."""
    spec = importlib.util.spec_from_file_location("kanban_noagent_watchdog", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def wd(monkeypatch, tmp_path):
    """Load the script isolated from any per-board config or env overrides.

    - chdir to an empty tmp dir so no `.kanban-watchdog.json` is picked up.
    - Remove every delivery-related env var so defaults apply.
    - Point STATE_FILE into tmp so real state is never touched.
    """
    monkeypatch.chdir(tmp_path)
    # Provide an isolated board identity so the module imports cleanly
    # (it hard-exits when KANBAN_BOARD is missing).
    monkeypatch.setenv("KANBAN_BOARD", "test-board")
    for var in ("DISCORD_THREAD_ID", "DISCORD_WEBHOOK_URL",
                "KANBAN_CRON_JOB_ID", "KANBAN_STATE_FILE", "KANBAN_USE_DISCORD_WEBHOOK",
                "KANBAN_EXPECTED_DELIVER"):
        monkeypatch.delenv(var, raising=False)
    mod = load_watchdog()
    # Isolate persistent side effects for each test.
    monkeypatch.setattr(mod, "STATE_FILE", str(tmp_path / "state.json"))
    return mod


def fake_ls(rows):
    """Build `hermes kanban ls`-style stdout rows: id status assignee title."""
    return "\n".join(f"abc123 {task_id} {status} {assignee} {title}"
                     for task_id, status, assignee, title in rows) + "\n"


class Recorder:
    """Capture emitted reports instead of posting them anywhere."""

    def __init__(self):
        self.calls = []

    def __call__(self, lines):
        self.calls.append("\n".join(lines))


def wire(wd, monkeypatch, ls_stdout, recorder=None):
    """Stub run()/emit()/remove_self() so main() can execute safely offline."""
    rec = recorder or Recorder()
    monkeypatch.setattr(wd, "run", lambda cmd: ls_stdout)
    monkeypatch.setattr(wd, "emit", rec)
    monkeypatch.setattr(wd, "remove_self", lambda: None)
    return rec


# ─── 1. Default destination ──────────────────────────────────────────────────
def test_default_destination_is_shared_channel(wd):
    """With no env/config override, the destination must be the shared channel."""
    assert wd.DISCORD_THREAD_ID == EXPECTED_DEFAULT_CHANNEL
    assert wd.DEFAULT_DISCORD_CHANNEL_ID == EXPECTED_DEFAULT_CHANNEL


def test_env_override_still_wins(wd, monkeypatch):
    """Backwards compatibility: explicit env override beats the shared default."""
    monkeypatch.setenv("DISCORD_THREAD_ID", "999888777666555444")
    mod = load_watchdog()
    assert mod.DISCORD_THREAD_ID == "999888777666555444"


def test_config_override_still_wins(tmp_path, monkeypatch):
    """Backwards compatibility: per-board config file value beats the default."""
    (tmp_path / ".kanban-watchdog.json").write_text(json.dumps({
        "board": "some-board",
        "discord_thread_id": "111122223333444555",
    }))
    monkeypatch.chdir(tmp_path)
    for var in ("DISCORD_THREAD_ID", "KANBAN_STATE_FILE", "KANBAN_CRON_JOB_ID"):
        monkeypatch.delenv(var, raising=False)
    mod = load_watchdog()
    assert mod.DISCORD_THREAD_ID == "111122223333444555"


# ─── 2. Blocked report includes board ID ─────────────────────────────────────
def test_blocked_report_includes_board_id(wd, monkeypatch, tmp_path):
    """Blocked report must contain a visible `Board ID: <slug>` line."""
    rec = wire(wd, monkeypatch, fake_ls([
        ("t_deadbeef", "blocked", "dev-python", "Fix the login bug"),
        ("t_cafe0000", "ready", "reviewer", "Review the fix"),
    ]))
    with pytest.raises(SystemExit) as exc:
        wd.main()
    assert exc.value.code == 0
    assert len(rec.calls) == 1
    msg = rec.calls[0]
    assert "BLOCKED t_deadbeef (dev-python): Fix the login bug" in msg
    assert f"Board ID: {wd.BOARD}" in msg


def test_blocked_report_not_resent_for_same_signature(wd, monkeypatch):
    """Existing dedupe behavior intact: identical blocked signature stays silent."""
    wire(wd, monkeypatch, fake_ls([
        ("t_deadbeef", "blocked", "dev-python", "Fix the login bug"),
        ("t_cafe0000", "ready", "reviewer", "Review the fix"),
    ]))
    with pytest.raises(SystemExit):
        wd.main()  # first tick emits
    # Second tick: same blocked task, unchanged title -> no new report.
    rec2 = Recorder()
    wd.emit = rec2
    with pytest.raises(SystemExit):
        wd.main()
    assert rec2.calls == []


# ─── 3. All-done report includes board ID ────────────────────────────────────
def test_all_done_report_includes_board_id(wd, monkeypatch):
    """All-done report must contain a visible `Board ID: <slug>` line."""
    rec = wire(wd, monkeypatch, fake_ls([
        ("t_aaaa1111", "done", "dev-python", "First task"),
        ("t_bbbb2222", "done", "reviewer", "Second task"),
    ]))
    with pytest.raises(SystemExit) as exc:
        wd.main()
    assert exc.value.code == 0
    assert len(rec.calls) == 1
    msg = rec.calls[0]
    assert "complete: 2 done, 0 blocked." in msg
    assert f"Board ID: {wd.BOARD}" in msg


def test_all_done_reported_only_once(wd, monkeypatch):
    """All-done fires exactly once; second tick over the same board is silent."""
    wire(wd, monkeypatch, fake_ls([("t_aaaa1111", "done", "dev-python", "Only task")]))
    with pytest.raises(SystemExit):
        wd.main()
    rec2 = Recorder()
    wd.emit = rec2
    with pytest.raises(SystemExit):
        wd.main()
    assert rec2.calls == []


# ─── 4. Ordinary in-progress states are silent ───────────────────────────────
def test_in_progress_states_emit_nothing(wd, monkeypatch):
    """running/todo/ready mixes must produce zero reports."""
    rec = wire(wd, monkeypatch, fake_ls([
        ("t_aaaa1111", "running", "dev-python", "In flight"),
        ("t_bbbb2222", "todo", "reviewer", "Queued"),
        ("t_cccc3333", "ready", "worker", "Ready to go"),
    ]))
    with pytest.raises(SystemExit) as exc:
        wd.main()
    assert exc.value.code == 0
    assert rec.calls == []
    # State was still refreshed despite silence.
    saved = json.loads(Path(wd.STATE_FILE).read_text())
    assert saved["last_snapshot"] == {
        "t_aaaa1111": "running", "t_bbbb2222": "todo", "t_cccc3333": "ready",
    }


# ─── 5. active_task_ids + state-default robustness ───────────────────────────
def test_active_task_ids_filters_scope(wd, monkeypatch, tmp_path):
    """active_task_ids limits reporting to the listed tasks only."""
    monkeypatch.setattr(wd, "ACTIVE_TASK_IDS", {"t_watchme"})
    rec = wire(wd, monkeypatch, fake_ls([
        ("t_watchme", "blocked", "dev-python", "Watched task blocked"),
        ("t_ignored0", "blocked", "other", "Ignored task blocked"),
    ]))
    with pytest.raises(SystemExit):
        wd.main()
    assert len(rec.calls) == 1
    assert "t_watchme" in rec.calls[0]
    assert "t_ignored0" not in rec.calls[0]


def test_corrupt_state_file_falls_back_to_defaults(wd, monkeypatch):
    """A corrupt/unreadable state file must not crash the tick or lose reports."""
    Path(wd.STATE_FILE).write_text("{not valid json")
    rec = wire(wd, monkeypatch, fake_ls([
        ("t_aaaa1111", "done", "dev-python", "Task"),
    ]))
    with pytest.raises(SystemExit):
        wd.main()
    # Clean-default behavior: all-done was never reported before, so it fires.
    assert len(rec.calls) == 1
    assert "Board ID:" in rec.calls[0]


def test_missing_state_file_defaults_shape(wd):
    """load_state() on a missing file returns the canonical default dict."""
    wd.STATE_FILE = "/nonexistent/path/state.json"
    state = wd.load_state()
    assert state["reported_blocked_signatures"] == {}
    assert state["reported_all_done"] is False
    assert state["removed_after_done"] is False
    assert state["last_snapshot"] == {}
    assert state["updated_at"] is None


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
