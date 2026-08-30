# Internal-only Traefik routing

This Compose project defines a separate Traefik instance for trusted-LAN HTTP testing on `192.168.1.115`. It does not configure TLS, Cloudflare, public DNS, a router port-forward, or Traefik's insecure API. The only published socket is `192.168.1.115:80`; Traefik listens on non-root container port 8080.

Nothing in this project changes or recreates an application container. `intake-api` is reached by its existing Docker DNS name over the external `proxy-public` network. Its live labels were found using `intake.localhost`, not `intake.coveredon.com`; the Docker-provider opt-in constraint excludes those unchanged labels, and the reviewed file-provider route below supplies the protected LAN route. Phish and filedrop are transitional `host.docker.internal` routes using Docker's `host-gateway` mapping. The Hermes backend remains defined for a possible future route, but no router currently exposes it.

## Routes

| Internal hostname | Destination | Notes |
|---|---|---|
| `phish.192-168-1-115.nip.io` | UI `:8088`; API paths to `:8012` | `/v1*`, `/health`, `/docs*`, `/redoc*`, and `/openapi.json` are sent to the API for same-origin UI use. |
| `phish-api.192-168-1-115.nip.io` | native Phish API `:8012` | All paths go to the API. |
| `kanban.192-168-1-115.nip.io` | Reserved; disabled | No router is configured. The native Hermes route redirects to `/login`, which returns 404 under this hostname, and Hermes has no separate proxy authentication. Keep disabled pending a working login flow and a real auth boundary. |
| `filedrop.192-168-1-115.nip.io` | trip-filedrop `:8787` | Transitional; uploaded content is sensitive. |
| `intake.192-168-1-115.nip.io` | `intake-api:8000` | Directly over `proxy-public`; does not use host port 8017. |
| `traefik.192-168-1-115.nip.io/dashboard/` | `api@internal` | Dashboard/API route protected by the same IP allowlist; `api.insecure` is disabled. |

Every router uses `internal-only`, which permits IPv4 loopback, RFC1918 space (`10/8`, `172.16/12`, `192.168/16`), IPv6 loopback, and IPv6 ULA (`fc00::/7`). Traefik uses the connection peer address; this configuration does not opt into trusting arbitrary forwarded headers.

### Trusted-LAN caveats

An address allowlist is network-boundary control, not authentication. Any client on an allowed private network—including a compromised Wi-Fi/LAN device—can reach these routes. NAT or a future proxy in front of Traefik can also make many clients appear to share one allowed private source. Do not add router forwarding, a tunnel, or a public listener, and do not configure forwarded-header trust without enumerating known proxy addresses.

`nip.io` is a public wildcard DNS service even though these names resolve to a private address. DNS queries may leave the LAN; use local DNS/hosts entries instead if hostname query privacy matters.

The Hermes dashboard has no separate proxy authentication in this stack and is an administrative interface. Its native route redirects to `/login`, but that path returns 404 when requested through the routed hostname. The `kanban` hostname is therefore reserved and its router is intentionally disabled pending both a working login flow and a real authentication boundary. The backend service definition remains unused so a future, separately reviewed change can wire it safely. Never expose Hermes ports 8642, 8644, or 8655.

The native services' existing direct LAN ports remain reachable independently of Traefik and therefore bypass its allowlist. Closing those publications/binds requires separate, controlled application changes and is outside this no-restart deployment.

## Adding a new app

Prefer the Docker provider when the app is containerized. It discovers only containers with both `traefik.enable=true` and this stack's explicit `traefik.internal-lan=true` opt-in; this prevents unrelated or pre-existing Traefik-labeled containers from being imported. Attach the app container to the existing external `proxy-public` network and add labels like these, replacing `myapp`, the hostname, and port with app-specific values:

```yaml
services:
  myapp:
    networks: [proxy-public]
    labels:
      - "traefik.enable=true"
      - "traefik.internal-lan=true"
      - "traefik.docker.network=proxy-public"
      - "traefik.http.routers.myapp.entrypoints=web"
      - "traefik.http.routers.myapp.rule=Host(`myapp.192-168-1-115.nip.io`)"
      - "traefik.http.routers.myapp.middlewares=internal-only@file"
      - "traefik.http.routers.myapp.service=myapp"
      - "traefik.http.services.myapp.loadbalancer.server.port=8000"

networks:
  proxy-public:
    external: true
    name: proxy-public
```

For a native host process, use a transitional file-provider route through `host.docker.internal` (provided by this stack's `host-gateway` mapping). Define both its `http.services` load-balancer URL and its `http.routers` entry in `traefik/dynamic/routes.yml`; use the `web` entrypoint, a nip.io `Host` rule, and the `internal-only` middleware. Record the native process/port owner and the rollback in the change: editing this file reloads Traefik's watched dynamic configuration but does not restart the native process, and rollback is removal/reversion of only the new router and service. If a restart of the native app is required, treat that as a separate, explicitly approved application change.

After checking the Docker socket GID as below, validate and recreate only this Traefik service when Compose or static configuration changes:

```sh
DOCKER_SOCKET_GID="$(stat -c '%g' /var/run/docker.sock)" docker compose config --quiet
DOCKER_SOCKET_GID="$(stat -c '%g' /var/run/docker.sock)" docker compose up -d --no-deps --force-recreate lan-traefik
```

For dynamic-only changes, the file provider reloads `traefik/dynamic/routes.yml` automatically; if an explicit reload is needed, use `DOCKER_SOCKET_GID="$(stat -c '%g' /var/run/docker.sock)" docker compose restart lan-traefik`. These commands target only this Compose project's Traefik service and do not recreate or restart existing apps. Keep every route internal-only: do not add TLS/Cloudflare, public DNS or listeners, router forwarding/tunnels, forwarded-header trust, or secrets to labels or tracked configuration.

## Preflight and operator-run start

The container runs as UID 65532. To read a typical mode-0660 Docker socket without running as root, its primary GID must match the socket group. Check the value and pass it at every Compose invocation:

```sh
stat -c '%g' /var/run/docker.sock
DOCKER_SOCKET_GID="$(stat -c '%g' /var/run/docker.sock)" docker compose config --quiet
```

The default GID `999` is only a convenience and must not be assumed correct. A read-only socket mount prevents filesystem writes to the socket but does not make the Docker API itself read-only; access to it remains security-sensitive. A separately managed, verb-filtering Docker socket proxy would be a stronger future boundary.

After inspection, the operator can start only this project (not application services):

```sh
DOCKER_SOCKET_GID="$(stat -c '%g' /var/run/docker.sock)" docker compose up -d
```

Useful checks after an approved start include `docker compose ps`, the health status, `ss -ltnp` showing only `192.168.1.115:80`, and requests from both allowed and disallowed source networks. No HTTPS check is expected.

## Rollback

Rollback affects only this uniquely named Compose project:

```sh
DOCKER_SOCKET_GID="$(stat -c '%g' /var/run/docker.sock)" docker compose down
```

This removes the new Traefik container while leaving the external `proxy-public` network and every existing application container/process intact. Because all application ports and labels are unchanged, their pre-existing direct access paths remain the fallback. Do not add `--remove-orphans`, delete `proxy-public`, or recreate `intake-api` as part of rollback.
