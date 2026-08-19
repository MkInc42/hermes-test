#!/usr/bin/env python3
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

def load_cwd_config() -> dict:
    """Allow one reusable watchdog script with per-board config in workdir.

    Cron has no env-field, so board-specific jobs should set `workdir` to a
    directory containing `.kanban-watchdog.json` instead of creating a new
    wrapper script per board.
    """
    cfg_path = Path.cwd() / ".kanban-watchdog.json"
    if not cfg_path.exists():
        return {}
    try:
        return json.loads(cfg_path.read_text())
    except Exception as exc:
        print(f"ERROR: failed to read {cfg_path}: {exc}")
        sys.exit(1)


CONFIG = load_cwd_config()
BOARD = str(os.environ.get("KANBAN_BOARD") or CONFIG.get("board", "")).strip()
JOB_ID = str(os.environ.get("KANBAN_CRON_JOB_ID") or CONFIG.get("job_id", "")).strip()
STATE_FILE = str(
    os.environ.get("KANBAN_STATE_FILE")
    or CONFIG.get("state_file")
    or os.path.expanduser(f"~/.hermes/cron/{BOARD or 'kanban'}-watchdog-state.json")
)
DISCORD_WEBHOOK_URL = str(os.environ.get("DISCORD_WEBHOOK_URL") or CONFIG.get("discord_webhook_url", "")).strip()
DISCORD_THREAD_ID = str(os.environ.get("DISCORD_THREAD_ID") or CONFIG.get("discord_thread_id", "")).strip()
USE_DISCORD_WEBHOOK = (
    str(os.environ.get("KANBAN_USE_DISCORD_WEBHOOK") or CONFIG.get("use_discord_webhook", ""))
    .strip()
    .lower()
    in {"1", "true", "yes", "on"}
)
# expected_deliver is the Hermes cron delivery target the job SHOULD use.
# When set and starting with "discord:", the script enforces the full
# thread-safe format (discord:<parent_channel_id>:<thread_id>) and rejects
# the short format (discord:<thread_id>) that silently lands outside the thread.
EXPECTED_DELIVER = str(os.environ.get("KANBAN_EXPECTED_DELIVER") or CONFIG.get("expected_deliver", "")).strip()

if not BOARD:
    print("ERROR: KANBAN_BOARD is required via env or .kanban-watchdog.json in the cron workdir")
    sys.exit(1)


def validate_expected_deliver(deliver_value: str) -> None:
    """Validate expected_deliver Discord format at startup.

    Requirements (from BRIEF.md):
    - If the value starts with ``discord:`` it MUST match
      ``discord:<parent_channel_id>:<thread_id>`` (two numeric IDs, colon-separated).
    - Short format ``discord:<thread_id>`` (single ID, missing parent channel) is
      rejected with an actionable error explaining the required format.
    - Non-Discord and empty values are allowed unchanged — local/origin delivery
      is not affected.

    Called early so a misconfigured board watchdog fails loudly instead of
    silently delivering to the wrong Discord destination.
    """
    if not deliver_value or not deliver_value.startswith("discord:"):
        return  # non-Discord or unset — no validation needed
    full_format = r"^discord:\d+:\d+$"
    if re.match(full_format, deliver_value):
        return  # valid: discord:<parent_id>:<thread_id>
    # Reject short format or anything else that starts with discord: but isn't valid
    print(
        f"ERROR: expected_deliver '{deliver_value}' has an invalid Discord thread format.\n"
        "For Discord threads the correct Hermes cron delivery format is:\n"
        f"  discord:<parent_channel_id>:<thread_id>\n"
        "Example: discord:1524966774754250884:1539686107782979725\n"
        "\n"
        "Fix the 'expected_deliver' field in .kanban-watchdog.json and the cron job's\n"
        "'deliver' setting to use the full parent_id:thread_id format."
    )
    sys.exit(1)


def verify_cron_deliver_matches(expected: str) -> None:
    """Cross-check cron job's actual ``Deliver`` field against expected_deliver.

    Runs ``hermes cron list`` and parses the output to find the job matching
    *JOB_ID*. If found, compares its ``Deliver`` field with *expected*. A
    mismatch prints a warning (non-fatal — the config validation above already
    enforced the format). This is best-effort: if the cron list output format
    changes or JOB_ID isn't set, the check is skipped.
    """
    if not JOB_ID or not expected:
        return  # nothing to verify against
    try:
        out = subprocess.run(
            ["hermes", "cron", "list"],
            capture_output=True, text=True, timeout=30,
        )
        if out.returncode != 0:
            return  # cron list unavailable, skip silently
    except Exception:
        return  # any failure is non-fatal

    # Parse output for the matching job's Deliver field.
    # Format looks like:
    #   <job_id> [active|paused]
    #     Name:      ...
    #     Deliver:   <value>
    in_job = False
    actual_deliver = None
    for line in out.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith(JOB_ID):
            in_job = True
            continue
        if in_job and stripped.startswith("Deliver:"):
            actual_deliver = stripped.split("Deliver:", 1)[1].strip()
            break
        # A new job-id line starts after a blank line or another job header
        # Reset in_job if we see a new job-id pattern (hex id at line start)
        if in_job and re.match(r"^[0-9a-f]{12}\b", stripped):
            break  # crossed into next job without finding Deliver

    if actual_deliver and actual_deliver != expected:
        print(
            f"WARNING: cron job '{JOB_ID}' has Deliver='{actual_deliver}' "
            f"but expected_deliver='{expected}'.\n"
            "Consider updating the cron job's deliver setting to match "
            "expected_deliver in .kanban-watchdog.json."
        )


# Run delivery validation at startup so misconfigured boards fail early.
validate_expected_deliver(EXPECTED_DELIVER)
verify_cron_deliver_matches(EXPECTED_DELIVER)


def run(cmd: list[str]) -> str:
    env = os.environ.copy()
    env.pop("HERMES_DELEGATED_CHILD_CONTEXT", None)
    env["HERMES_KANBAN_BOARD"] = BOARD
    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if res.returncode != 0:
        msg = (res.stderr or res.stdout or "").strip()
        print(f"ERROR: {' '.join(cmd)} failed: {msg}")
        sys.exit(res.returncode or 1)
    return res.stdout


def load_state() -> dict:
    p = Path(STATE_FILE)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {
        "reported_blocked_signatures": {},
        "reported_all_done": False,
        "removed_after_done": False,
        "last_snapshot": {},
        "updated_at": None,
    }


def save_state(state: dict) -> None:
    p = Path(STATE_FILE)
    p.parent.mkdir(parents=True, exist_ok=True)
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    p.write_text(json.dumps(state, indent=2, sort_keys=True))


LINE_RE = re.compile(r"^[^\s]+\s+(t_[a-z0-9]+)\s+(\w+)\s+(\S+)\s+(.*)$")


def parse_ls(output: str) -> list[dict]:
    tasks = []
    for raw in output.splitlines():
        line = raw.rstrip()
        m = LINE_RE.match(line)
        if not m:
            continue
        task_id, status, assignee, title = m.groups()
        tasks.append(
            {
                "id": task_id,
                "status": status,
                "assignee": assignee,
                "title": title.strip(),
            }
        )
    return tasks


def remove_self() -> None:
    if not JOB_ID:
        return
    env = os.environ.copy()
    env.pop("HERMES_DELEGATED_CHILD_CONTEXT", None)
    subprocess.run(
        ["hermes", "cron", "remove", JOB_ID],
        capture_output=True,
        text=True,
        env=env,
    )


def emit(lines: list[str]) -> None:
    message = "\n".join(lines).strip()
    if not message:
        return
    if USE_DISCORD_WEBHOOK and DISCORD_WEBHOOK_URL and DISCORD_THREAD_ID:
        post_to_discord_webhook(message)
        return
    print(message)


def post_to_discord_webhook(message: str) -> None:
    payload = {"content": message}
    url = DISCORD_WEBHOOK_URL
    sep = "&" if "?" in url else "?"
    url = f"{url}{sep}thread_id={urllib.parse.quote(DISCORD_THREAD_ID)}"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "Hermes Kanban Watchdog"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            if resp.status < 200 or resp.status >= 300:
                raise RuntimeError(f"discord webhook returned HTTP {resp.status}")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        raise RuntimeError(f"discord webhook HTTP {e.code}: {body}") from e
    except Exception as e:
        raise RuntimeError(f"discord webhook post failed: {e}") from e


state = load_state()
ls_output = run(["hermes", "kanban", "ls"])
tasks = parse_ls(ls_output)
state["last_snapshot"] = {t["id"]: t["status"] for t in tasks}

if not tasks:
    save_state(state)
    sys.exit(0)

blocked = [t for t in tasks if t["status"] == "blocked"]
if blocked:
    lines = []
    for t in blocked:
        sig = f"{t['id']}:{t['status']}:{t['title']}"
        if state["reported_blocked_signatures"].get(t["id"]) == sig:
            continue
        state["reported_blocked_signatures"][t["id"]] = sig
        lines.append(f"BLOCKED {t['id']} ({t['assignee']}): {t['title']}")
    save_state(state)
    if lines:
        emit([f"Kanban board '{BOARD}' has blocked work:", *lines])
    sys.exit(0)

all_done = all(t["status"] == "done" for t in tasks)
if all_done and not state.get("reported_all_done"):
    state["reported_all_done"] = True
    save_state(state)
    emit([
        f"Kanban board '{BOARD}' is complete.",
        f"All {len(tasks)} task(s) are done.",
    ])
    remove_self()
    state["removed_after_done"] = True
    save_state(state)
    sys.exit(0)

save_state(state)
sys.exit(0)
