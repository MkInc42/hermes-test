# Internal Traefik inventory and route plan

Inventory captured 2026-08-30 12:09 EDT on host `192.168.1.115`.

Scope is trusted-LAN testing only. The intended DNS-free names use the sslip.io pattern below; no public DNS, Cloudflare tunnel, router forwarding, TLS termination, or production cutover is part of this plan.

## Runtime inventory

### Active native processes

| Process / project | Bind | Port | Current evidence | Routing classification |
|---|---:|---:|---|---|
| Phish Triage API (three dev instances) | `127.0.0.1` on two instances; `0.0.0.0` on LAN instance | 8001, 8002, **8012** | Uvicorn from `/home/black/phish-triage-engine`; `/health` returns `{"status":"ok"}` on all three | Use **8012** only. The loopback instances are not reachable from a Traefik container through host-gateway. |
| Phish Triage static UI | `0.0.0.0` | **8088** | `python3 -m http.server ... --directory frontend`; HTTP 200 | Transitional host route. |
| FamBridge / local Django app | `0.0.0.0` | **5630** | Django `runserver` from `/home/black/projects/family-school-coordination-saas`; HTTP 200 | Transitional host route. |
| Hermes dashboard / Kanban | `0.0.0.0` | **9119** | `hermes dashboard ... --host 0.0.0.0`; `/dashboard/` returns HTTP 302 | Conditional admin route; LAN-only and not safe for any wider exposure because no separate proxy auth was observed. |
| Hermes gateway / API listeners | `0.0.0.0` | 8642, 8644 | Hermes gateway process | Do not expose as browser routes in this phase. |
| Honcho/Codex proxy | `0.0.0.0` | 8655 | Hermes proxy process | Do not expose. |

### Active Docker containers

| Container | Backend port | Docker network(s) | Host publication | Routing classification |
|---|---:|---|---|---|
| `intake-api` | 8000 | `proxy-public` (`172.24.0.3`) | `127.0.0.1:8017` | **Docker-routable.** Route directly over `proxy-public`; do not use the loopback host publication. |
| `intake-db` | 5432 | `proxy-public` (`172.24.0.2`) | none | Database only; never route or publish through Traefik. |
| `trip-filedrop` | 8787 | `trip-filedrop_default` (`172.19.0.2`) | `0.0.0.0:8787` | Transitional host route now. Preferred follow-up is to attach it to `proxy-public`, remove the host port, and add labels. |
| `covered-on-meta-dm-relay-relay-1` | 8000 | `covered-on-meta-dm-relay_default` (`172.21.0.2`) | `0.0.0.0:8000` | Do not expose by default; this is an integration/message relay, not a requested browser app. Port 8000 is occupied. |
| `hermes-kg-postgres` | 5432 | `hermes-knowledge-graph_default` (`172.18.0.2`) | `0.0.0.0:5432` | Database only; this broad LAN publication is a security finding, not a route target. Do not touch in this task. |
| `phish-triage-db` | 5432 | `phish-triage-engine_default` (`172.28.0.2`) | `127.0.0.1:55432` | Database only; never route. |
| `pia-vpn` | none | `phish-triage-engine_default` | none | VPN sidecar; never route. |

No Traefik container is currently running. The existing external `proxy-public` bridge network is present and currently contains only `intake-api` and `intake-db`.

## Proposed subdomain map

All names below assume Traefik's LAN HTTP entrypoint on host port 80 and the host's current LAN address. Native targets use `host.docker.internal` backed by Docker's `host-gateway` mapping; those entries are explicitly transitional.

| Hostname | Route / priority | Backend target | Status and safety notes |
|---|---|---|---|
| `phish.192-168-1-115.sslip.io` | `/v1/*`, `/health`, `/docs` | `http://host.docker.internal:8012` | Active Phish Triage API. Bind is LAN-wide and the API is intentionally privacy-sensitive. Keep this hostname LAN-only; do not route 8001/8002. |
| `phish.192-168-1-115.sslip.io` | catch-all `/` | `http://host.docker.internal:8088` | Active dependency-free Phish Triage UI. Lower priority than `/v1` and `/health` routes so UI fallback cannot capture API requests. Transitional until the UI is containerized. Same-origin proxying avoids the UI's split-origin CORS setup. |
| `hermes.192-168-1-115.sslip.io` | `/dashboard/*` and redirect target `/` as needed | `http://host.docker.internal:9119` | **Conditional.** Hermes/Kanban admin UI is active and responds, but no proxy authentication was observed. Only add this route when the operator accepts trusted-LAN unauthenticated admin exposure; never publish it outside the LAN. |
| `fambridge.192-168-1-115.sslip.io` | catch-all `/` | `http://host.docker.internal:5630` | Active local Django/FamBridge preview. Transitional native route. Keep local/LAN only; no public tunnel. |
| `trip.192-168-1-115.sslip.io` | catch-all `/` | `http://host.docker.internal:8787` | Active file-drop UI/API. Sensitive uploaded files and no container healthcheck were observed. LAN-only, and preferably protect with app authentication before sharing beyond the operator's trusted workstation. Transitional until network labels replace the `0.0.0.0:8787` publication. |
| `intake.192-168-1-115.sslip.io` | `/api/*`, `/health` | `http://intake-api:8000` on `proxy-public` | Active Covered On intake API, healthy, root `/docs` available. Existing labels default to `intake.coveredon.com`; an internal sslip hostname override is required before the route matches. Never route `intake-db`. |
| `cowa.192-168-1-115.sslip.io` | `/api/*`, `/health` | `http://cowa-backend:8000` on `proxy-public` | **Reserved, not active.** The COWA compose definition exists and is already designed for `proxy-public`, but no `cowa-backend` container is running. Its current labels use `api.coveredon.com`; do not start it until those production-oriented hostnames and any required secrets are replaced with internal test values. |

## Ports and exposure decisions

- Port 80 is not listening and is the clean Traefik HTTP bind candidate. Port 443 is also not listening, but HTTPS is intentionally out of scope for this internal HTTP test phase.
- Host port 8000 is occupied by `covered-on-meta-dm-relay-relay-1`; Traefik must not bind there.
- Host port 5432 is occupied and published by `hermes-kg-postgres`; do not reuse or expose it through Traefik.
- Host port 8017 is a loopback-only publication for `intake-api`; Traefik must use Docker DNS on `proxy-public`, not `host.docker.internal:8017`.
- Ports 8012, 8088, 5630, 8787, and 9119 are currently LAN-reachable native/host publications. The proposed Traefik routes centralize access but do not remove those direct ports yet.
- Do not expose 22, 3389, 5900, 631, 8642, 8644, 8655, 5432, 55432, or any Docker socket/database endpoint.
- Stopped projects were observed, including the old `covered-on-portal` containers. Do not start or revive them as part of this inventory task; some compose definitions reuse port 8000 and would conflict with the relay.

## Implementation handoff and restart gates

1. Create a new, uniquely named Traefik stack on `proxy-public`, binding only the intended LAN HTTP port. Use Docker provider for `intake-api`/future COWA and a file provider with `host-gateway` for the native transitional backends.
2. The intake labels currently interpolate the default hostname `intake.coveredon.com`. Applying the sslip hostname through the existing compose file will require a controlled intake-api recreation, for example:
   `TRAEFIK_HOST=intake.192-168-1-115.sslip.io docker compose -f /home/black/covered-on-intake-api/docker-compose.yml up -d intake-api`
   Do not run that from this inventory task; obtain the operator's restart approval in the implementation task and verify the container remains healthy afterward.
3. Do not restart relay, trip-filedrop, FamBridge, Hermes, databases, or any unrelated service during Traefik installation. The initial file-provider routes avoid an app restart for native services and preserve rollback.
4. If the implementation removes `trip-filedrop`'s direct port or adds `proxy-public`, treat that as a separate controlled container recreation and record the exact command before executing it.
5. Validate each route with LAN Host headers, confirm no route exists for databases or Hermes model/gateway listeners, and verify that Traefik is listening only on the intended internal interface/port.
