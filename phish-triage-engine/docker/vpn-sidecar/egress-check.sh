#!/bin/sh
set -eu

# Keep the identity service fixed so this privileged namespace helper cannot be
# repurposed as a general fetcher. DNS goes to a public resolver through tun0;
# curl is then address-pinned and cannot fall back to Docker/host DNS.
[ "${1:-}" = "https://api.ipify.org" ] || exit 1
address="$(dig +short +time=3 +tries=1 @1.1.1.1 api.ipify.org A | awk 'NR == 1 {print; exit}')"
[ -n "$address" ] || exit 1
exec curl --fail --silent --show-error --max-time 5 \
    --resolve "api.ipify.org:443:$address" https://api.ipify.org
