#!/usr/bin/env python3
"""
Covered On — SEO Request Worker
No-LLM pipeline: watches Discord for new SEO audit requests, runs the audit,
and posts results back to the channel.

Designed for cron (no_agent=true): zero LLM calls, pure HTTP + subprocess.
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

# ─── Config ──────────────────────────────────────────────────────────────────
CHANNEL_ID = "1530730268875296919"
DISCORD_API = "https://discord.com/api/v10"
WEBHOOK_URL = os.environ.get("SEO_WEBHOOK_URL")
AUDIT_DIR = os.path.expanduser("~/covered-on-seo-audit")
STATE_FILE = os.path.expanduser("~/.hermes/cron/seo-request-worker-state.json")
HERMES_ENV = os.path.expanduser("~/.hermes/.env")

# Maximum age of messages to process (in seconds) — skip old ones on first run
MAX_AGE_SECONDS = 3600  # 1 hour


def load_bot_token():
    """Read DISCORD_BOT_TOKEN from ~/.hermes/.env"""
    if not os.path.exists(HERMES_ENV):
        print(f"ERROR: {HERMES_ENV} not found", file=sys.stderr)
        sys.exit(1)
    with open(HERMES_ENV) as f:
        for line in f:
            line = line.strip()
            if line.startswith("DISCORD_BOT_TOKEN="):
                val = line.split("=", 1)[1].strip().strip('"').strip("'")
                return val
    print("ERROR: DISCORD_BOT_TOKEN not found", file=sys.stderr)
    sys.exit(1)


def load_state():
    """Load last processed message ID from state file."""
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"last_message_id": None}


def save_state(state):
    """Persist state to file."""
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def discord_get(url, token):
    """GET request to Discord API."""
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bot {token}",
        "User-Agent": "CoveredOn-SeoWorker/1.0",
    })
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"ERROR: Discord API {url}: {e.code} {e.read().decode()}", file=sys.stderr)
        return None


def discord_post_webhook(payload):
    """POST a message to Discord via webhook URL."""
    if not WEBHOOK_URL:
        print("WARN: No webhook URL configured — set SEO_WEBHOOK_URL", file=sys.stderr)
        return None
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        WEBHOOK_URL,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "CoveredOn-SeoWorker/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read()
            return json.loads(body) if body else {"ok": True}
    except urllib.error.HTTPError as e:
        print(f"WARN: Webhook post failed: {e.code} {e.read().decode()}", file=sys.stderr)
        return None


def fetch_messages(token, after_id=None):
    """Fetch messages from the channel. Returns newest-first."""
    url = f"{DISCORD_API}/channels/{CHANNEL_ID}/messages?limit=5"
    if after_id:
        url += f"&after={after_id}"
    return discord_get(url, token) or []


def parse_request(message_text):
    """
    Parse website URL and email from a Discord message.
    Formspree sends messages like:
      "New submission from <email>: https://example.com"
    or:
      "Website: https://example.com\nEmail: user@example.com"
    """
    url_match = re.search(r'https?://[^\s<>"]+', message_text)
    email_match = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', message_text)

    url = url_match.group(0) if url_match else None
    email = email_match.group(0) if email_match else None
    return url, email


def run_audit(url, output_dir):
    """Execute the audit pipeline as a subprocess."""
    os.makedirs(output_dir, exist_ok=True)
    pipeline_script = os.path.join(AUDIT_DIR, "pipeline.py")
    if not os.path.exists(pipeline_script):
        print(f"ERROR: {pipeline_script} not found", file=sys.stderr)
        return None

    cmd = [
        sys.executable, pipeline_script,
        url,
        "--output", output_dir,
        "--max-urls", "100",
        "--max-depth", "3",
    ]
    print(f"Running: {' '.join(cmd)}")
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    print(result.stdout)
    if result.returncode != 0:
        print(f"ERROR: Pipeline exited {result.returncode}: {result.stderr}", file=sys.stderr)
        return None

    # Parse report path from output
    report_match = re.search(r'Report:\s+(\S+)', result.stdout)
    report_path = report_match.group(1) if report_match else None
    pages_match = re.search(r'Pages:\s+(\d+)', result.stdout)
    pages = pages_match.group(1) if pages_match else "?"
    duration_match = re.search(r'Duration:\s+([\d.]+)s', result.stdout)
    duration = duration_match.group(1) if duration_match else "?"

    return {"report_path": report_path, "pages": pages, "duration": duration, "url": url}


def main():
    token = load_bot_token()
    state = load_state()
    last_id = state.get("last_message_id")
    now = datetime.now(timezone.utc).timestamp()

    print(f"[{datetime.now().isoformat()}] Checking for new SEO requests...")
    print(f"  Last processed message ID: {last_id}")

    messages = fetch_messages(token, after_id=last_id)
    if not messages:
        print("  No new messages.")
        save_state(state)
        return

    print(f"  Found {len(messages)} new message(s)")

    # Process newest first, update last_id as we go
    # messages are returned newest-first by Discord
    processed = 0
    for msg in reversed(messages):  # oldest first for processing order
        msg_id = msg["id"]
        content = msg.get("content", "")
        timestamp = msg.get("timestamp", "")
        
        # Parse timestamp
        try:
            msg_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
        except (ValueError, AttributeError):
            msg_time = 0

        # Skip messages older than MAX_AGE (first-run guard)
        if msg_time and (now - msg_time) > MAX_AGE_SECONDS:
            print(f"  Skipping old message {msg_id} from {timestamp}")
            continue

        # Skip bot's own messages (posted via the worker's result post),
        # but NOT webhook messages from Formspree
        if not msg.get("webhook_id") and msg.get("author", {}).get("bot"):
            print(f"  Skipping own bot message {msg_id}")
            continue

        url, email = parse_request(content)
        if not url:
            print(f"  Skipping message {msg_id}: no URL found")
            continue

        print(f"  Processing: URL={url}, Email={email}")
        
        # Run audit
        domain_part = re.sub(r'[^a-z0-9]', '-', url.split("//")[-1].split("/")[0])
        timestamp_part = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_dir = os.path.join(AUDIT_DIR, "audits", f"{domain_part}-{timestamp_part}")
        
        result = run_audit(url, output_dir)
        
        if result:
            summary = (
                f"✅ **SEO Audit Complete**\n"
                f"**URL:** {result['url']}\n"
                f"**Pages crawled:** {result['pages']}\n"
                f"**Duration:** {result['duration']}s\n"
                f"**Report saved to:** `{result['report_path']}`"
            )
            if email:
                summary += f"\n**Requested by:** {email}"
            discord_post_webhook({"content": summary})
            print(f"  ✓ Report: {result['report_path']}")
        else:
            discord_post_webhook({
                "content": f"❌ **SEO Audit Failed**\n**URL:** {url}\nCheck logs for details."
            })
            print(f"  ✗ Audit failed for {url}")

        # Update last processed ID
        current_last = state.get("last_message_id") or "0"
        if int(msg_id) > int(current_last):
            state["last_message_id"] = msg_id
        processed += 1

    save_state(state)
    print(f"  Done. Processed {processed} request(s).")


if __name__ == "__main__":
    main()
