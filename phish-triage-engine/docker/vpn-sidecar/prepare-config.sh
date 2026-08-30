#!/bin/sh
set -eu

source_profile=${1:?source profile required}
runtime_profile=${2:?runtime profile required}
temporary="${runtime_profile}.tmp"
umask 077
trap 'rm -f "$temporary"' EXIT HUP INT TERM

# OpenVPN 2.6 deprecates the legacy compression directives.  PIA profiles can
# still contain a bare `compress`; translate only that compatibility surface to
# asymmetric receive-only support.  Never enable outbound compression, and
# never modify the operator-owned, read-only source profile.
awk '
BEGIN { compatibility = 0; existing_policy = ""; unsafe = 0 }
# `scramble` came from a historical PIA-patched OpenVPN client and is not an
# OpenVPN 2.6 directive.  It obfuscated (but did not encrypt) the transport.
# Stock endpoints generally accept the normal TLS transport; if one does not,
# normal OpenVPN negotiation fails while the pre-tunnel kill switch stays up.
/^[[:space:]]*scramble([[:space:]]|$)/ { next }
/^[[:space:]]*(compress|comp-lzo)([[:space:]]|$)/ {
    compatibility = 1
    next
}
/^[[:space:]]*allow-compression[[:space:]]+/ {
    value = $2
    sub(/[;#].*$/, "", value)
    if (value != "no" && value != "asym") unsafe = 1
    existing_policy = value
    next
}
{ print }
END {
    if (unsafe) exit 42
    if (compatibility || existing_policy == "asym") print "allow-compression asym"
    else print "allow-compression no"
}
' "$source_profile" >"$temporary" || {
    printf '%s\n' "VPN profile compatibility conversion failed" >&2
    exit 1
}
chmod 0600 "$temporary"
mv "$temporary" "$runtime_profile"
trap - EXIT HUP INT TERM
