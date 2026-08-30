#!/bin/sh
set -eu

source_profile=${1:?source profile required}
runtime_profile=${2:?runtime profile required}
temporary="${runtime_profile}.tmp"
umask 077
trap 'rm -f "$temporary"' EXIT HUP INT TERM

# The sidecar is built with Tunnelblick's pinned XOR patch. Preserve PIA's
# historical `scramble obfuscate [mask]` spelling, including the older bare
# form (which the patched parser treats as the xormask named "obfuscate").
# Reject every other scramble form so a profile can never silently fall back
# to a different wire protocol.
#
# OpenVPN 2.6 deprecates the legacy compression directives. Translate only that
# compatibility surface to asymmetric receive-only support. Never enable
# outbound compression or modify the operator-owned, read-only source profile.
awk '
BEGIN { compatibility = 0; existing_policy = ""; unsafe = 0; unsupported_scramble = 0 }
/^[[:space:]]*scramble([[:space:]]|$)/ {
    line = $0
    sub(/[[:space:]]*[;#].*$/, "", line)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
    fields = split(line, parts, /[[:space:]]+/)
    if (parts[1] != "scramble" || parts[2] != "obfuscate" || fields > 3) unsupported_scramble = 1
    print
    next
}
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
    if (unsafe || unsupported_scramble) exit 42
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
