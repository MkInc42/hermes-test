# Gate 0 — Principal Reviewer Initial Blocking Decisions

**Project:** Covered On Portal Django MVP
**Reviewer:** Principal Reviewer
**Date:** 2026-08-17
**Workspace:** /home/black/covered-on-portal-django

---

## 1. Stack Coherence Verdict

**Django 6.1 + standalone Postgres + Authentik OIDC + Docker Compose: APPROVED.**

The stack is coherent and well-suited for MVP:

- **Django 6.1** is the correct target. All critical packages (mozilla-django-oidc, Whitenoise, psycopg2-binary or psycopg3) support it today. If any package forces a temporary pin, document the blocker and pin to the last compatible Django version + file an upgrade ticket.
- **Standalone Postgres** avoids SQLite concurrency limits and managed-DB complexity for MVP. Easy to promote to cloud Postgres later.
- **Authentik OIDC** reuses existing infra identity source. No new credential stores. Existing user provisioning patterns carry over.
- **Docker Compose** wraps the three services (app, db) cleanly for local portability.

**Secondary defaults (agent-decided, documented here for clarity):**

| Choice | Default | Rationale |
|---|---|---|
| Base image | `python:3.12-slim-bookworm` | Slim + pinned Debian codename avoids rolling-tag surprises |
| OIDC library | `mozilla-django-oidc` | Standard, maintained, documented — no reason to diverge |
| Static files | Whitenoise | Standard Django container pattern |
| UI rendering | Server-side Django templates only | No frontend framework for MVP |
| DB driver | `psycopg[binary]` (psycopg 3) | Modern, async-compatible, maintained |
| CSS | Bootstrap 5 via CDN (or pinned NPM if build step exists) | Fast MVP; swap to Tailwind in a later iteration if needed |
| PK type | Auto-incrementing integer (`BigAutoField`) | Simpler than UUIDs for MVP; no distributed-ID requirement |
| Session backend | Django DB-backed sessions | Simplest; no Redis dependency for MVP |
| Logging | JSON to stdout via Django dictConfig | Container-native; consumed by `docker compose logs` |

---

## 2. Blocking Decisions

These are frozen before any implementation code is written.

### 2.1 No user self-registration

All user/account provisioning flows through Authentik admin. The Django app exposes **zero** registration endpoints, sign-up forms, or user-creation views. Every authenticated user must exist in Authentik first.

### 2.2 No REST API in MVP

All interactions are server-rendered Django templates/views. DRF is **not** included. This eliminates the auth-per-endpoint attack surface for MVP. A REST layer can be added in a future iteration if clients need API access.

### 2.3 Explicit migrate, not auto-migrate

Migrations run via `docker compose exec web python manage.py migrate` — documented in a Makefile or README. **No** entrypoint-triggered auto-migration guard. Auto-migration at container start can mask migration errors, cause silent roll-forward failures in compose restarts, and create a footgun where `migrate` runs on every `docker compose up`.

### 2.4 `DEBUG=False` in all Compose environments

Including local dev. Debug-thrown tracebacks are an information-leak vector that can expose environment variables, source paths, and data. Use `django-extensions` / `runserver_plus` / `Werkzeug`-style debugging tools explicitly when needed; never rely on `settings.DEBUG=True` for day-to-day dev troubleshooting.

### 2.5 Session cookie security baseline

All session cookies must set:
- `HttpOnly` — prevent JS access
- `SameSite=Lax` — reasonable CSRF protection baseline
- `Secure=True` — required when behind TLS (flag in docs for prod)
- `SESSION_COOKIE_AGE` to a reasonable session lifetime (default 2 hours or configurable via env)

### 2.6 Postgres version pinned to explicit tag

`postgres:16` or `postgres:17` — whatever is current stable in Docker Hub at implementation time. **Not** `postgres:latest`. Pinning prevents unexpected PG major-version upgrades from breaking the data directory or requiring re-init.

### 2.7 Covered On branding only — zero MLPS copy

The brief is emphatic and this is a blocking requirement: login page, dashboard, portal pages, email templates (if any) must use Covered On branding exclusively. Any MLPS reference that survived from earlier portal work is a launch-blocking finding.

---

## 3. Agent Autonomy Boundaries

### 3.1 Agents decide without asking Reknown

| Domain | Examples |
|---|---|
| Project structure | App names, directory layout (`portal/`, `accounts/`, `services/`), whether to use single vs multi-app |
| Model field details | Field types (int PKs, CharField lengths, DateField vs DateTimeField), ordering, `Meta` options, `__str__` |
| Forms & validation | Form class design, field ordering, validation rules, error message style |
| Templates & styling | Template structure and partials, CSS classes, layout minor choices, Bootstrap version pin |
| Tests | Test file structure, factory approach, test data values, test method ordering |
| Docker details | Compose port mappings (`8000:8000`), service names, health check endpoint path, volume mount paths |
| Environment config | `.env.example` variable names and defaults, `settings.py` env var loading pattern |
| Auth mapping logic | How Authentik claims map to app roles/`is_staff`/`is_superuser` — but see 3.2 for limits |
| Logging config | Log format, output destination, level thresholds per environment |
| Helper utilities | `utils.py` helpers, decorators, middleware ordering inside Django's default MIDDLEWARE |

### 3.2 Agents MUST escalate to Reknown

| Domain | Why |
|---|---|
| **Authentik client/application registration** | Infra config, not code — needs Authentik admin access and tenant provisioning decision |
| **Any new third-party service** | Email provider, CDN, monitoring, analytics, error tracking — each has cost/Legal/ops implications |
| **Frontend framework or build step** | Adding React/Vite/Webpack/npm build fundamentally changes the architecture; only Reknown can approve scope expansion |
| **REST API / DRF** | Changes auth surface area and scope — blocked by Gate 0 decision 2.2 unless Reknown overrides |
| **Django version deviation** | If Django 6.1 blocks on a critical dependency, the alternative version + upgrade path needs sign-off |
| **Database engine change** | Moving off Postgres to MySQL, SQLite in prod, or adding Redis — each has correctness and ops implications |
| **Security exceptions** | `@csrf_exempt`, disabling auth on a route, hardcoded API keys, skipping auth middleware on any view |
| **Production deployment** | Hosting provider, domain, TLS, reverse proxy, secrets management, database hosting — Reknown approval required by brief |
| **Any pricing/billing model fields** | Adding costs, subscription tiers, payment fields to the data model is a business decision |
| **User-facing account deletion** | Self-service account deletion, data export, GDPR/CCPA flows — legal implications |

---

## 4. Pre-live Security & Quality Gates

These are non-negotiable launch checks. Every item must pass before production go-live.

### 4.1 Container-first verification
- `docker build` succeeds with zero warnings
- `docker compose up` brings the stack online
- Health endpoint (`/health/` or `/api/health/`) returns HTTP 200
- Static files serve correctly through Whitenoise in container mode
- Database migrations run clean on a fresh Postgres container

### 4.2 Auth adversarial review
- OIDC login redirects correctly to Authentik and back
- Logout clears session and redirects to a safe page (no open redirects)
- Session expiry forces re-authentication
- CSRF token present and validated on every POST
- No accessible URL path bypasses auth middleware
- Redirect parameters cannot be manipulated for open-redirect attacks
- Authentik logout also terminates Django session (RP-initiated logout)
- Login page has no "forgot password" flow unless Authentik handles it externally

### 4.3 Role isolation (data access control)
- Admin view: lists all clients, services, assignments, reports, documents
- Client view: ONLY their own assigned services and documents. No admin list, no other client's data
- Direct URL manipulation: `/services/42/` must 404 or 403 for a client not assigned to service 42
- ID enumeration: sequential IDs do not leak "there exists a service at /services/43/" to unauthorized clients
- Demo/sample data: clearly flagged and never returned to a client as if it were their real data

### 4.4 Zero public debug surface
- `DEBUG=False` verified in the running container via a debug check endpoint
- No `/__debug__/`, `/debug/`, `/api/docs/`, or OpenAPI/Swagger endpoints
- No Django admin exposed — either admin lives under a non-obvious prefix or is gated by staff-only check + Authentik group
- Custom error pages (404, 403, 500) that do not leak stack traces, settings, or app internals
- No `SECRET_KEY` or other secrets visible in error responses

### 4.5 No secrets in repo
- `.env.example` is the only env file committed. Contains placeholder values only.
- `SECRET_KEY`, `DB_PASSWORD`, `AUTHENTIK_CLIENT_SECRET` never appear in tracked files
- Git history scanned before launch for accidental credential commits

### 4.6 Test suite passes
Minimum coverage:
- Models: `__str__`, constraints, default ordering
- Auth: claim-to-role mapping, group resolution, staff/superuser derivation
- Access control: admin views return admin data, client views return only their data, unauthenticated requests redirect to login
- Service assignment: listing, detail view, scoping per role
- Migrations: `makemigrations --check` produces no unapplied changes
- Health endpoint: returns 200 and expected JSON shape

### 4.7 UI copy audit
- Login page: "Covered On" branding only
- Dashboard header/h1: "Covered On Portal" or similar — no MLPS or other brand
- All page copy references actual built functionality; no "coming soon" or placeholder text
- Service names match Covered On's actual productized offerings, not MLPS service names
- No MLPS address, phone, email, or footer references

### 4.8 Browser QA (Playwright MCP)
- Login flow: navigate, click login, Authentik redirect, callback, land on correct dashboard
- Admin path: see client list, service list, assignment management (if built)
- Client path: see only own services, no admin links
- Desktop and mobile viewport verification
- Console errors: zero JS errors on login, dashboard, and client pages
- Navigation: logout → login redirect works, back-button after logout doesn't show cached data

---

## 5. Open Questions

**None that block foundation work.** The brief is well-specified. The decisions above cover all material design, security, and autonomy boundaries needed for implementation to begin.

One structural note for the kanban dispatch: Gate 0 is the parent node. Subsequent work lanes (foundation, backend, frontend, integration, review, QA) should be child tasks that depend on this gate being complete.

---

## Change Log

| Date | Author | Change |
|---|---|---|
| 2026-08-17 | Principal Reviewer | Initial Gate 0 review |