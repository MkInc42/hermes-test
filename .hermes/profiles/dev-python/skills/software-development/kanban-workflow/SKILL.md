---
name: kanban-workflow
description: "Operate Hermes kanban boards: profiles, workspaces, task lifecycle, failure recovery, and dispatcher management."
version: 1.2.0
author: agent
license: MIT
hermes:
  tags: [kanban, multi-agent, profiles, tasks, orchestration]
  related_skills: [hermes-agent]
---

# Kanban Workflow

Practical operational guide for Hermes kanban boards — the multi-agent task queue system. Covers what the CLI `--help` and docs don't: profile setup, workspace persistence, failure recovery, and dispatcher behavior.

## Triggers

Load this skill when:
- Creating, configuring, or troubleshooting kanban boards, tasks, profiles, or dispatchers
- A kanban task is stuck, blocked, crashed, or failing silently
- Setting up a worker profile for kanban task execution
- **A user asks to build ANY new project, codebase, or multi-file deliverable** — create a kanban board BEFORE writing any files. The user expects kanban orchestration, not direct file creation.
- User asks to "create a board and start the process" or similar

### CRITICAL: Kanban first, always

When the user asks you to build something (app, website, tool, any codebase with 3+ files):
1. Create a kanban board for the project FIRST
2. Create a triage task with `--triage` for auto-decomposition
3. Let the decomposer split it into children
4. Dispatch and let workers build

**NEVER start writing files manually before kanban is set up.** The user explicitly expects kanban orchestration behind the scenes. Starting manually then trying to retro-fit kanban wastes time and loses the decomposition benefits.

## Profile Setup for Worker Profiles

Kanban workers run under named profiles. Every worker profile MUST have:

```bash
# 1. Set the model (required — workers default to free rate-limited models otherwise)
hermes config set model.default deepseek/deepseek-v4-pro --profile <name>

# 2. Copy API keys from default profile
cp ~/.hermes/.env ~/.hermes/profiles/<name>/.env

# 3. (Optional) Add a SOUL.md for specialized identity
# Write to ~/.hermes/profiles/<name>/SOUL.md
```

### Common pitfall: "RateLimitError [HTTP 429]" on worker startup
**Cause:** Profile has no model configured, defaults to a free rate-limited model like `google/gemma-4-31b-it:free`.
**Fix:** Set `model.default` for the profile and ensure `.env` has API keys.

### Common pitfall: Worker exits cleanly but task crashes
**Cause:** Profile can't reach the LLM (no API key, wrong model, rate limited). The worker process exits cleanly (rc=0) but never calls `kanban_complete`, which the dispatcher treats as a protocol violation.
**Fix:** Verify profile config with `hermes config show --profile <name>` — confirm model and API keys are set.

## Workspace Types

Three workspace kinds, controlled by `--workspace` on task creation:

| Kind | CLI flag | Persists? | Cleanup |
|------|----------|-----------|---------|
| `scratch` | (default) | ❌ No | Auto-deleted on task completion |
| `dir` | `--workspace dir:/absolute/path` | ✅ Yes | Never deleted |
| `worktree` | `--workspace worktree --branch wt/name` | ✅ Yes | Git worktree |

### Rule: Always use `dir:` for tasks producing files the user wants to keep

```bash
# RIGHT — files survive:
hermes kanban create --workspace dir:/home/black/output --assignee designer "Task"

# WRONG — files vanish on completion:
hermes kanban create --assignee researcher "Task"
```

Scratch is designed for pipeline tasks where child output is consumed by a parent and intermediate workspaces are waste.

## Task Lifecycle & Failure Recovery

### States
```
triage → todo → ready → running → done
                   ↓         ↓
               blocked    crashed (auto-retry up to failure_limit)
```

### Circuit breaker
A task auto-blocks after `failure_limit` consecutive spawn failures (default: 2, configurable via `kanban.failure_limit` or per-task `--max-retries N`).

**Recovery sequence when a task is blocked:**
```bash
# 1. Diagnose
hermes kanban show <task_id>
hermes kanban log <task_id>

# 2. Fix the root cause (model, API key, etc.)

# 3. Unblock and re-dispatch
hermes kanban unblock <task_id>
hermes kanban dispatch
```

### Manual dispatch
The dispatcher runs inside the gateway by default (`kanban.dispatch_in_gateway: true`). To force an immediate dispatch tick:
```bash
hermes kanban dispatch
```

### Killing a stuck worker
If a task shows `running` but isn't making progress (no heartbeats):
```bash
# Find the PID from 'hermes kanban show <task_id>'
kill <pid>
# The dispatcher will reclaim the stale claim on next tick
```

## Board Management

```bash
# Create a board
hermes kanban boards create --name "Display Name" --default-workdir /path/to/output <slug>

# Switch to a board (subsequent commands operate on it)
hermes kanban boards create --switch <slug>

# Create a task with persistence
hermes kanban create \
  --workspace dir:/home/black/output \
  --assignee <profile> \
  --body "Task description" \
  "Task Title"

# Monitor a running task
hermes kanban show <task_id>
hermes kanban tail <task_id>         # live event stream
hermes kanban stats                  # board-level counts
hermes kanban assignees              # profile statuses

# List all runs for a task
hermes kanban runs <task_id>
```

### Decomposer setup (`--triage` prerequisite)

The `--triage` flag + `hermes kanban decompose` requires auxiliary model config. Without it, decompose times out silently. Set this once:

```bash
hermes config set auxiliary.triage_specifier.provider openrouter
hermes config set auxiliary.triage_specifier.model deepseek/deepseek-chat
hermes config set auxiliary.kanban_decomposer.provider openrouter
hermes config set auxiliary.kanban_decomposer.model deepseek/deepseek-chat
```

Verify with `hermes config show | grep -A3 auxiliary`. A cheaper model like `deepseek/deepseek-chat` works well — decomposition doesn't need the full reasoning power of v4-pro.

## Creating Specialized Worker Profiles

For distinct worker identities (e.g., researcher vs. designer):

```bash
# Clone from default (gets config, .env, skills)
hermes profile create <name> --clone-from default

# Set model
hermes config set model.default deepseek/deepseek-v4-pro --profile <name>

# Write custom identity
# Edit ~/.hermes/profiles/<name>/SOUL.md

# Verify
hermes config show --profile <name>
hermes profile list
```

Each profile gets:
- Isolated session history and memory
- Separate config and secrets
- Custom SOUL.md for task-specific identity
- Shortcut alias: `<name> chat` or `hermes chat -p <name>`

### Profile SOUL.md Examples

These are proven identity templates for specialized worker profiles:

**Cyber Threat Analyst** (`cyber-threat-analyst`): Principal Security Analyst for threat triage/review, phishing/domain investigations, infrastructure analysis, campaign correlation, and DFIR-style reporting. Output: investigation reports with risk scoring, source status, IOCs, and recommendations. Do not use for GitHub/local-project code reviews.

**Designer** (`designer`): Creative Director / UX Architect. Agency-grade output, boutique aesthetic. No frameworks (HTML5/CSS3/vanilla JS only). WCAG AA, Lighthouse 95+. Anti-template rules: no gradient heroes, no card grids, no Inter+Poppins, no generic CTAs, no counter animations.

**Automation** (`automation`): Senior n8n Workflow Architect. Python code actions preferred over JavaScript. Build for production: error handling, edge cases, idempotency, credential security. Design → implement → test → document workflow.

### Adding MCP Servers to a Profile

For profiles needing external tool access (e.g., n8n server for automation), add `mcp_servers` to the profile's `config.yaml` directly — bypass the interactive CLI which fails on self-signed certs:

```yaml
mcp_servers:
  server-name:
    url: "https://server.example.com/mcp-endpoint"
    headers:
      Authorization: "Bearer <token>"
    timeout: 180
    connect_timeout: 30
    ssl_verify: false    # REQUIRED for self-signed or expired certs
```

Prerequisite: `pip install mcp --break-system-packages`

**Common pitfall: SSL certificate errors.** If the server uses a self-signed or expired certificate, the MCP client will fail to connect. Always add `ssl_verify: false` for self-hosted/internal servers. The `hermes mcp add` CLI's interactive mode cannot handle SSL failures — use direct YAML config instead.

After adding, restart the profile's session. Discovered tools appear as `mcp_<server>_<tool_name>`.

### Renaming a profile

```bash
hermes profile rename <old_name> <new_name>
```

After renaming, any tasks assigned to the old name reference a stale assignee. Reassign them:
```bash
hermes kanban reassign <task_id> <new_name>
```

### Profile gateways

Each profile has its own gateway. If a profile's gateway is stopped, the dispatcher from the default gateway will still spawn workers for it. The profile gateway is only needed if you want that profile to receive messages independently.

## Parallel Task Orchestration

When dispatching multiple tasks that have dependency relationships, use this proven serial→parallel→serial pattern:

### Phase 1: Serial — foundation first
Dispatch the foundational task (the one everything else depends on) alone. Wait for it to complete before queuing anything else. Examples: backend scaffold, database schema, project skeleton.

### Phase 2: Parallel — independent workers
Once the foundation exists, assign and dispatch independent tasks together. They run concurrently and don't interfere. Example: auth module + inference engine (both depend on the DB schema but not on each other).

### Phase 3: Serial — integration last
After all phase-2 tasks complete, dispatch integration tasks. These often depend on multiple phase-2 outputs. Example: frontend-backend wiring, tree visualization (depends on inference engine output shape).

```bash
# Phase 1 — assign + dispatch ONE task
hermes kanban assign <foundation_task> default
hermes kanban dispatch

# Wait for completion (poll with hermes kanban ls), then:

# Phase 2 — assign + dispatch multiple independent tasks
hermes kanban assign <task_a> default
hermes kanban assign <task_b> default
hermes kanban dispatch     # spawns both

# Wait for BOTH to complete, then:

# Phase 3 — assign + dispatch final integration tasks
hermes kanban assign <integration_a> default
hermes kanban assign <integration_b> default
hermes kanban dispatch
```

### Pitfall: Parallel workers corrupting shared files

When two parallel tasks share the same `dir:` workspace AND both edit the same file (e.g., templates), one worker may read a partially-written or stale version and conclude "file is corrupted," then rewrite it from scratch — wiping the other worker's changes. This also manifests as **silent feature loss**: both workers create the same file independently, and last-write-wins drops features from the other.

Symptoms:
- Worker logs: "The file is corrupted. Let me write it fresh from scratch."
- Missing features: a button, route, or section that one worker added is gone
- Stale snapshots: one worker reads old content before the other's write lands
- Silent data loss: no merge conflict, just last-write-wins
- Most common when the decomposer gives both workers overlapping file ownership (e.g., backend worker decides templates are "missing" and creates its own, frontend worker also creates them)

**Prevention:**
- Split independent concerns into separate files (e.g., `codegen.py` for auth, `inference.py` for the engine, `main.py` for routing that depends on both). This is why phase-2 tasks should each write into distinct modules when possible.
- If two tasks MUST touch the same file, run them serially, not in parallel.
- After parallel phase completes, review shared files with `hermes kanban log <task>` to check for rewrite-then-restore patterns.
- Task bodies should explicitly list which files each worker owns — never leave it to worker judgment.

**Real reproduction:** `references/parallel-worker-template-corruption.md` — delete button silently lost from `show_row.html` when both backend and frontend workers created templates in parallel.

### Recovery: kill all workers, rebuild manually

When you see cascading corruption (duplicate imports, indentation errors, syntax errors, missing functions), the workers are in a destructive loop. Each one reads a partially-corrupted file, concludes it's broken, and rewrites it — wiping the other's changes. The cycle accelerates.

**Don't wait for them to recover. Kill and rebuild:**

```bash
# 1. Kill all running tasks on the board
hermes kanban reclaim <task_a>
hermes kanban reclaim <task_b>
# ... all running tasks

# 2. Reset to known-good state
cd <workspace>
git checkout HEAD -- .

# 3. Build the features sequentially yourself
# Workers are good at isolated features but terrible at shared files.
```

This happened with 4 parallel workers all editing `src/main.py` + `src/database.py` — recovery took 10 minutes manually vs. 45+ minutes of workers fighting each other.

**Root cause:** the decomposer gave overlapping file ownership to all 4 tasks (each needed to edit the same route file and database model). For future decompositions, add a synthesizer task that owns the shared files, and have children write to separate module files.

See also: `references/orchestration-pattern.md` for a worked example from a full-stack project.
See also: `references/plex-artwork-revert.md` for a real debugging case from a kanban-orchestrated homelab project — four failed approaches before finding the correct Plex REST sequence.

## Review-Blocked Tasks

Workers can self-block with `review-required` (via `kanban_block`) when they want human eyes on output before marking done. This is a deliberate block, not a failure.

**Handling review-blocked tasks:**
```bash
# 1. Check what was done
hermes kanban show <task_id>        # Read the comment + summary
ls -lh <workspace_path>             # Verify files exist

# 2. Review the work thoroughly
#    - Check files are present and correct
#    - grep for old/incorrect values
#    - Verify consistency across pages/files

# 3a. If satisfied — complete the task
hermes kanban complete <task_id>

# 3b. If changes needed — unblock to re-queue
hermes kanban unblock <task_id>
hermes kanban dispatch
```

## Task Creation Checklist

Before creating a kanban task:
- [ ] Board exists and is selected (`hermes kanban boards create --switch`)
- [ ] Workspace uses `dir:` not `scratch` (if output must persist)
- [ ] Assignee profile has model + API keys configured
- [ ] Assignee profile's gateway is running (for auto-dispatch)
- [ ] **Task body explicitly includes: `git init`, `git commit`, `gh repo create --private`, and `git push` steps** — workers have isolated context and won't know to push unless told. User will call this out if skipped.
- [ ] Body contains enough context for a worker with isolated memory to understand the task
- [ ] Supporting files are in the workspace directory before dispatch

### Why git push must be explicit

Workers complete their task body and stop. They don't know the broader project goals unless you tell them. If the task body says "build X, write tests, verify" they will do exactly that — and skip git + GitHub because it wasn't in the spec. Always include:

```
When complete: git init, commit all files, create private GitHub repo, and push.
```

Or even better, put it in the root synthesizer task body so it runs once after all children complete.

## Post-Completion Verification

When a task completes, verify the output before telling the user it's done:

```bash
# 1. Check files exist with expected sizes
find <workspace> -type f -exec ls -lh {} \;

# 2. Audit color palette (for website/design tasks)
grep -o '#[0-9A-Fa-f]\{6\}' <workspace>/css/style.css | sort -u

# 3. Hunt for old/incorrect values
grep -rn '<old_color_or_pattern>' <workspace>/ --include='*.html' --include='*.css'

# 4. Verify logos, fonts, key elements
grep -c 'logo-transparent' <workspace>/*.html
grep 'font-display\|font-body' <workspace>/css/style.css

# 5. Render-check in browser if available
# Serve with python3 -m http.server then browse each page

# 6. Verify Google Fonts are loading (not silently failing)
# Use browser_console: [...document.styleSheets].filter(s => s.href && s.href.includes('google'))
```

Never mark a task complete to the user without running at minimum steps 1-3.

### Common pitfall: Hardcoded localhost in integration tasks

When an integration worker wires an SPA to a backend API, it often leaves `API_BASE` or fetch URLs hardcoded to `http://localhost:PORT`. This works in the worker's browser-testing sandbox but breaks for anyone accessing from another machine on the network. **After integration tasks complete, verify:**

```bash
# Hunt for hardcoded localhost URLs in frontend files
grep -rn 'localhost:[0-9]' <workspace>/ --include='*.html' --include='*.js' --include='*.ts'
```

The fix: use relative URLs (`/api/...`) when the backend serves the frontend on the same origin, or a configurable base URL when they're on different origins.

### Common pitfall: Vision tool silently missing despite being enabled

The `vision` toolset can show as `✓ enabled` in `hermes tools list` but `vision_analyze` still won't appear in the agent's tool list. The `check_vision_requirements` function silently drops the tool when no vision provider resolves (defaults to Nous auth, which fails without `hermes auth`). Fix:

```bash
hermes config set auxiliary.vision.provider openrouter
hermes config set auxiliary.vision.model <model>
```

Verify with `hermes config show | grep -A3 auxiliary.vision`. Requires `/reset` to take effect.

## Post-Completion: Git & GitHub Tracking

After verifying output, set up version tracking for the workspace:

```bash
cd <workspace>
git init && git branch -m main
echo ".hermes/" > .gitignore
git add -A && git commit -m "Initial commit: <description>"
gh repo create <user>/<repo-name> --private \
  --description "<description>" \
  --source=. --remote=origin --push
```

**Always use `--private`** — never create a public GitHub repo without explicit permission.
Verify auth with `gh auth status` before pushing — expired tokens silently fail with HTTP 401.

## No-Agent Kanban Watchdog

The shared no-agent watchdog script at `~/.hermes/scripts/kanban-noagent-watchdog.py` provides reusable board monitoring for cron jobs. It stays silent unless a board transitions to blocked or all-done, then prints the update to stdout (which the cron scheduler delivers).

### Per-board config: `.kanban-watchdog.json`

Each board that uses the watchdog places this config file in the cron job's `workdir`:

```json
{
  "board": "<board-slug>",
  "job_id": "<cron-job-id>",
  "state_file": "/home/black/.hermes/cron/<board-slug>-watchdog-state.json",
  "expected_deliver": "discord:<parent_channel_id>:<thread_id>"
}
```

### Discord thread delivery enforcement

When the cron job delivers to a Discord thread, the cron `deliver` setting and the config's `expected_deliver` must use the **full thread-safe format**:

```
discord:<parent_channel_id>:<thread_id>
```

**Incorrect — short format (lands outside the thread):**
```
discord:1539686107782979725
```

**Correct — full format with parent channel + thread:**
```
discord:1524966774754250884:1539686107782979725
```

### How enforcement works

1. **Config validation:** At startup the script checks `expected_deliver`. If it starts with `discord:`, it must match `discord:\d+:\d+` (two numeric IDs). The short one-ID format is rejected with a clear error explaining the required format. Non-Discord and empty values are allowed without change.

2. **Cron cross-check:** If both `job_id` and `expected_deliver` are set, the script queries `hermes cron list` and compares the actual `Deliver` field against the expected value. A mismatch emits a non-fatal warning so you can correct the cron job's delivery target.

3. **Common failure mode:** A cron job configured with `discord:<thread_id>` alone (no parent channel) delivers outside the thread — the message lands in the wrong channel and isn't visible to thread participants. The format enforcement prevents this silently broken state.

### Setting up a new watchdog job

```bash
# 1. Create .kanban-watchdog.json in the workdir
# 2. Register the cron job:
hermes cron create \
  --schedule "*/5 * * * *" \
  --script kanban-noagent-watchdog.py \
  --deliver "discord:<parent_channel_id>:<thread_id>" \
  --workdir /path/to/workdir \
  --no-agent \
  "<Board Name> Watchdog"

# 3. Verify the job list shows the correct Deliver field:
hermes cron list
```
