#!/usr/bin/env python3
"""
MLPS Email Watcher v3 — No-LLM cron worker with crash-safe ledger-based dedup

Changes from v2:
- Replaced PID-file dispatch guard with crash-safe ledger check against the
  MLPS Executive Assistant's processed_emails.json ledger.  The ledger survives
  gateway restarts and process terminations.  If the ledger already shows
  "processing" or "completed" for a fingerprint, the watcher never re-dispatches
  regardless of whether a subprocess PID still exists on the system.
- Removed DISPATCH_PID_FILE entirely — PID files are not crash-safe.
- Still silent when nothing new.

Ledger note: the MLPS Executive Assistant maintains its own idempotency
ledger at ~/.hermes/cron/output/f7259af0f109/processed_emails.json keyed on
message_id|subject|date.  This watcher only decides WHAT needs attention and
whether the assistant already claimed it.  The assistant's processing loop
(move to folder → acknowledge → do work → final response → move to Completed)
is untouched.
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta

# ─── Config ──────────────────────────────────────────────────────────────────
STATE_FILE = os.path.expanduser("~/.hermes/cron/mlps-email-watcher-state.json")
DISPATCH_LOG = os.path.expanduser("~/.hermes/cron/output/mlps-email-dispatch.log")
# Crash-safe ledger maintained by the MLPS Executive Assistant itself.
ASSISTANT_LEDGER = os.path.expanduser(
    "~/.hermes/cron/output/f7259af0f109/processed_emails.json"
)

INCOMING = "MLPS: Incoming"
PROCESSING = "MLPS: Processing"
COMPLETED = "MLPS: Completed"
AWAITING = "MLPS: Awaiting Response"
INBOX = "INBOX"

# Known MLPS stakeholders (Doris + team)
KNOWN_SENDERS = {
    "msladydps@gmail.com": "Doris Brookins",
    "bmanradge@gmail.com": "Bryan M",
}

MAX_AGE_HOURS = 24      # first-run guard for Incoming (skip ancient backlog)
STALE_HOURS = 2         # re-alert after this long in Incoming/Processing
DISPATCH_COOLDOWN_MIN = 10  # don't stack dispatches more often than cron interval

HERMES_BIN = "/home/black/.local/bin/hermes"
PROFILE = "mlps-executive-assistant"

# ─── Timeout hardening (v3.1) ────────────────────────────────────────────────
# Bounded retry policy for himalaya folder queries: one 30-second initial
# attempt plus two retries capped at 60 seconds each, with a short backoff
# between attempts.  A failed query returns None so main() can tell it apart
# from a legitimately empty folder ([]) and refuse to act on partial state.
INITIAL_TIMEOUT_SECONDS = 30
RETRY_TIMEOUT_SECONDS = 60
MAX_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 2


# ─── State ───────────────────────────────────────────────────────────────────
def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {
        "last_uid": None,
        "processed_uids": [],
        "reported": {},   # fingerprint -> {uid, subject, from, reported_at}
        "handled": {},    # fingerprint -> {subject, from, handled_at}
        "last_dispatch_at": None,
        "notes": "v3: ledger-based dedup; no PID file",
    }


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=1)


# ─── Crash-safe ledger check ─────────────────────────────────────────────────
def load_assistant_ledger():
    """Load the assistant's processed_emails.json as a crash-safe claim store.

    This ledger is the single source of truth that survives gateway restarts,
    process kills, and PID-file orphans.  If a fingerprint is present with
    state 'processing' or 'completed', the watcher MUST NOT re-dispatch.
    """
    if not os.path.exists(ASSISTANT_LEDGER):
        return {}
    try:
        with open(ASSISTANT_LEDGER) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def is_claimed_in_ledger(fp, ledger):
    """Return True if fingerprint is already in-flight or done per the ledger."""
    entry = ledger.get(fp)
    if entry is None:
        return False
    state = entry.get("state") or ""
    return state in ("processing", "completed", "failed")


# ─── Himalaya helpers ────────────────────────────────────────────────────────
def _concise_failure_reason(stderr, timed_out, returncode):
    """Build a one-line, secret-free reason for a failed himalaya call.

    Raw stderr can contain credentials or multi-line IMAP chatter, so only
    the first line is kept and any line mentioning authentication is dropped.
    """
    if timed_out:
        return f"timed out after {RETRY_TIMEOUT_SECONDS}s"
    first_line = (stderr or "").strip().splitlines()
    detail = ""
    for line in first_line:
        low = line.lower()
        if "password" in low or "token" in low or "login" in low or "auth" in low:
            continue  # never echo auth-related stderr — may contain secrets
        detail = line.strip()
        break
    return f"exit {returncode}: {detail}" if detail else f"exit {returncode}"


def run_himalaya(args):
    """Run himalaya with bounded retries; return stdout on success, else None.

    Policy: one 30-second initial attempt followed by two retries capped at
    60 seconds each, with a short backoff between attempts.  Both timeouts
    and transient nonzero exits are retried.  On exhaustion, prints ONE
    concise folder-specific diagnostic to stderr and returns None so the
    caller can distinguish failure from empty output.
    """
    cmd = ["himalaya"] + args
    last_reason = "unknown error"
    for attempt in range(1, MAX_ATTEMPTS + 1):
        timeout = INITIAL_TIMEOUT_SECONDS if attempt == 1 else RETRY_TIMEOUT_SECONDS
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=timeout)
        except subprocess.TimeoutExpired:
            last_reason = _concise_failure_reason("", timed_out=True,
                                                  returncode=None)
            if attempt < MAX_ATTEMPTS:
                time.sleep(RETRY_BACKOFF_SECONDS)
                continue
        except OSError as e:
            # himalaya missing/unreadable will not fix itself — fail fast.
            print(f"ERROR: himalaya {' '.join(args)}: cannot execute: {e}",
                  file=sys.stderr)
            return None
        else:
            if result.returncode == 0:
                return result.stdout
            last_reason = _concise_failure_reason(result.stderr, timed_out=False,
                                                  returncode=result.returncode)
            if attempt < MAX_ATTEMPTS:
                time.sleep(RETRY_BACKOFF_SECONDS)
                continue
    print(f"ERROR: himalaya {' '.join(args)} failed after "
          f"{MAX_ATTEMPTS} attempts ({last_reason})", file=sys.stderr)
    return None


def list_folder(folder, page_size=50):
    """Return the folder's envelopes, [] when legitimately empty, None on failure."""
    output = run_himalaya(["envelope", "list", "--folder", folder,
                           "--page-size", str(page_size), "--output", "json"])
    if output is None:
        return None
    output = output.strip()
    if not output:
        # Successful query with no output = genuinely empty folder.
        return []
    try:
        envelopes = json.loads(output)
    except json.JSONDecodeError:
        print(f"ERROR: could not parse himalaya output for {folder}", file=sys.stderr)
        return None
    if not isinstance(envelopes, list):
        print(f"ERROR: unexpected himalaya payload type for {folder}", file=sys.stderr)
        return None
    return envelopes


def envelope_from(env):
    f = env.get("from")
    if isinstance(f, dict):
        return f.get("name", ""), f.get("addr", "")
    return "", str(f or "")


def fingerprint(env):
    _, addr = envelope_from(env)
    return f"{addr.lower().strip()}|{env.get('subject', '')}|{env.get('date', '')}"


def sender_label(env):
    name, addr = envelope_from(env)
    addr_lower = addr.lower().strip()
    for known_addr, label in KNOWN_SENDERS.items():
        if known_addr in addr_lower:
            return label
    return name or addr


def is_known_sender(env):
    _, addr = envelope_from(env)
    addr_lower = addr.lower().strip()
    return any(known in addr_lower for known in KNOWN_SENDERS)


def parse_date(date_str):
    if not date_str:
        return None
    s = date_str.strip().replace(" ", "T", 1)
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def is_unread(env):
    return "Seen" not in (env.get("flags") or [])


# ─── Auto-dispatch ───────────────────────────────────────────────────────────
def dispatch_assistant(report_lines):
    """Spawn the MLPS Executive Assistant in the background to process.

    Uses ledger-based dedup (crash-safe) instead of a PID file.
    """
    prompt = (
        "PROCESS THE MLPS EMAILS LISTED BELOW, found by the MLPS email watcher. "
        "Follow the cron-email-pipeline two-phase pattern: claim each email "
        "(move from its folder to 'MLPS: Processing'), send an immediate "
        "acknowledgment to the sender, do the work, send a final response "
        "(success/partial/failure), then move the email to 'MLPS: Completed'. "
        "Update the idempotency ledger at "
        "~/.hermes/cron/output/f7259af0f109/processed_emails.json as you go. "
        "Use MLPS brand conventions and sign 'MLPS Executive Assistant'. "
        "Verify each send appears in Sent Mail before declaring done. "
        "Emails found:\n\n"
        + "\n".join(report_lines)
    )
    os.makedirs(os.path.dirname(DISPATCH_LOG), exist_ok=True)
    with open(DISPATCH_LOG, "a") as log:
        log.write(f"\n[{datetime.now(timezone.utc).isoformat()}] DISPATCH {PROFILE}:\n{prompt}\n")
        log.flush()
        proc = subprocess.Popen(
            [HERMES_BIN, "-p", PROFILE, "chat", "-q", prompt],
            stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    return proc.pid


# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    state = load_state()
    reported = state.setdefault("reported", {})
    handled = state.setdefault("handled", {})
    now = datetime.now(timezone.utc)

    # 0. Load crash-safe ledger from the assistant's own records.
    assistant_ledger = load_assistant_ledger()

    # 1. Snapshot all five required folders uniformly before any state change
    #    or dispatch: a failed query (None) is NOT an empty folder ([]), and
    #    acting on a partial snapshot risks missed or duplicate dispatches.
    #    Fail closed on the first unavailable folder with one concise message.
    snapshots = {}
    for folder in (INCOMING, PROCESSING, COMPLETED, AWAITING, INBOX):
        page_size = 100 if folder == INBOX else 50
        envelopes = list_folder(folder, page_size=page_size)
        if envelopes is None:
            # run_himalaya/list_folder already printed the single concise
            # folder-specific diagnostic — here we just fail closed.
            sys.exit(1)
        snapshots[folder] = envelopes

    incoming = snapshots[INCOMING]
    processing = snapshots[PROCESSING]
    completed = snapshots[COMPLETED]
    awaiting = snapshots[AWAITING]

    # Fingerprints that are already in the pipeline (Incoming/Processing)
    pipeline_fps = {fingerprint(e) for e in incoming + processing}
    # Fingerprints that are finished (Completed/Awaiting) -> handled
    finished_fps = {fingerprint(e) for e in completed + awaiting}

    # Mark handled from folder state
    for env in completed + awaiting:
        fp = fingerprint(env)
        if fp and fp not in handled:
            handled[fp] = {
                "subject": env.get("subject", ""),
                "from": envelope_from(env)[1],
                "handled_at": now.isoformat(),
            }

    # 2. Primary: new mail in MLPS: Incoming
    new_emails = []
    for env in incoming:
        fp = fingerprint(env)
        if fp in reported or fp in handled:
            continue
        # Crash-safe: skip if assistant already claimed in ledger
        if is_claimed_in_ledger(fp, assistant_ledger):
            continue
        age = parse_date(env.get("date", ""))
        if age and (now - age) > timedelta(hours=MAX_AGE_HOURS):
            continue
        new_emails.append(env)

    # 3. INBOX sweep: known-sender mail not in any MLPS folder.
    #    INBOX is already part of the uniform snapshot above.
    missed = []
    for env in snapshots[INBOX]:
        if not is_known_sender(env):
            continue
        fp = fingerprint(env)
        if fp in pipeline_fps or fp in finished_fps:
            continue
        if fp in reported:
            continue
        # Crash-safe: skip if assistant already claimed in ledger
        if is_claimed_in_ledger(fp, assistant_ledger):
            continue
        age = parse_date(env.get("date", ""))
        if age and (now - age) > timedelta(hours=MAX_AGE_HOURS):
            continue
        missed.append(env)

    # 4. Stale: reported but never handled, still in Incoming/Processing
    #    Also skip if assistant has a ledger claim (subprocess may be alive).
    stale = []
    for folder, env in [(INCOMING, e) for e in incoming] + [(PROCESSING, e) for e in processing]:
        fp = fingerprint(env)
        if fp not in reported or fp in handled:
            continue
        if is_claimed_in_ledger(fp, assistant_ledger):
            continue
        reported_at = parse_date(reported[fp].get("reported_at", "")) or now
        if (now - reported_at) > timedelta(hours=STALE_HOURS):
            stale.append((folder, env))

    # 5. Build report
    report_lines = []
    sections = []
    for env in new_emails:
        uid = env.get("id")
        sections.append(f"NEW (MLPS: Incoming, UID {uid})")
        report_lines.append(
            f"- [{sections[-1]}] From: {sender_label(env)} <{envelope_from(env)[1]}> | "
            f"Subject: {env.get('subject','(no subject)')} | Date: {env.get('date','')}"
        )
    for env in missed:
        sections.append(f"MISSED LABEL (in INBOX, UID {env.get('id')})")
        report_lines.append(
            f"- [{sections[-1]}] From: {sender_label(env)} <{envelope_from(env)[1]}> | "
            f"Subject: {env.get('subject','(no subject)')} | Date: {env.get('date','')}"
        )
    for folder, env in stale:
        sections.append(f"STALE (in {folder}, UID {env.get('id')})")
        report_lines.append(
            f"- [{sections[-1]}] From: {sender_label(env)} <{envelope_from(env)[1]}> | "
            f"Subject: {env.get('subject','(no subject)')} | Date: {env.get('date','')}"
        )

    # 6. Update state for newly reported emails
    for env in new_emails + missed:
        fp = fingerprint(env)
        reported[fp] = {
            "uid": env.get("id"),
            "subject": env.get("subject", ""),
            "from": envelope_from(env)[1],
            "reported_at": now.isoformat(),
        }

    # 7. Dispatch if there is work AND the assistant's ledger has no claim
    should_dispatch = bool(new_emails or missed or stale)
    dispatched = False
    if should_dispatch:
        last = state.get("last_dispatch_at")
        cooldown_ok = True
        if last:
            try:
                last_dt = datetime.fromisoformat(last)
                cooldown_ok = (now - last_dt) > timedelta(minutes=DISPATCH_COOLDOWN_MIN)
            except ValueError:
                cooldown_ok = True
        if cooldown_ok:
            try:
                pid = dispatch_assistant(report_lines)
                state["last_dispatch_at"] = now.isoformat()
                dispatched = True
                print(f"→ Auto-dispatched {PROFILE} (pid {pid}) to process {len(report_lines)} email(s).")
            except Exception as e:
                print(f"ERROR: auto-dispatch failed: {e}", file=sys.stderr)
        else:
            print(f"⚠ Dispatch cooldown active ({DISPATCH_COOLDOWN_MIN} min) — not spawning a new assistant run.")
    else:
        # There was work but the ledger claims it's already in-flight — safe.
        pass

    # Legacy fields
    all_incoming_uids = [str(e["id"]) for e in incoming if e.get("id")]
    if all_incoming_uids:
        state["last_uid"] = str(max(int(u) for u in all_incoming_uids))
    state["processed_uids"] = sorted(set(state.get("processed_uids", [])) | {str(e["id"]) for e in new_emails if e.get("id")})
    save_state(state)

    # 8. Output notification (delivered to Discord). Silent when nothing new.
    if not report_lines:
        return

    print("=" * 60)
    print(f"📬 MLPS EMAIL WATCHER — {len(report_lines)} item(s) need attention")
    print(f"Folder: {INCOMING} + INBOX sweep")
    print("=" * 60)
    for line in report_lines:
        print(line)
    if dispatched:
        print("")
        print("Processing has been auto-dispatched to the MLPS Executive Assistant.")
    elif should_dispatch:
        print("")
        print("Processing NOT auto-dispatched (see warning above).")
    print("")
    print(f"[{now.isoformat()}] Watcher v3 — ledger-based dedup (crash-safe), no PID file")


if __name__ == "__main__":
    main()