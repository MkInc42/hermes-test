#!/bin/sh
set -eu

profile=${1:?runtime profile required}
mapping="${profile}.remote-map"
temporary="${profile}.pinned"
umask 077
: >"$mapping"
trap 'rm -f "$mapping" "$temporary"' EXIT HUP INT TERM

awk '$1 == "remote" { print $2 }' "$profile" | sort -u |
while IFS= read -r host; do
    address=""
    case "$host" in
        *[!0-9.]*|*.*.*.*.*) ;;
        *.*.*.*) address="$host" ;;
    esac
    if [ -z "$address" ]; then
        for resolver in ${PTE_VPN_DNS_RESOLVERS:-}; do
            address=$(dig +short +time=3 +tries=1 "@$resolver" "$host" A |
                awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print; exit }')
            [ -n "$address" ] && break
        done
    fi
    [ -n "$address" ] || exit 1
    printf '%s\n' "$address" | awk -F. '
        NF != 4 { exit 1 }
        { for (i=1; i<=4; i++) if ($i !~ /^[0-9]+$/ || $i > 255) exit 1 }
        $1 == 0 || $1 == 10 || $1 == 127 || $1 >= 224 { exit 1 }
        $1 == 100 && $2 >= 64 && $2 <= 127 { exit 1 }
        $1 == 169 && $2 == 254 { exit 1 }
        $1 == 172 && $2 >= 16 && $2 <= 31 { exit 1 }
        $1 == 192 && ($2 == 0 || $2 == 168) { exit 1 }
        $1 == 198 && ($2 == 18 || $2 == 19 || $2 == 51) { exit 1 }
        $1 == 203 && $2 == 0 && $3 == 113 { exit 1 }
    ' || exit 1
    printf '%s %s\n' "$host" "$address" >>"$mapping"
done
[ -s "$mapping" ] || exit 1

awk 'NR == FNR { pinned[$1] = $2; next }
$1 == "remote" {
    if (!($2 in pinned)) exit 43
    $2 = pinned[$2]
}
{ print }
' "$mapping" "$profile" >"$temporary" || exit 1
chmod 0600 "$temporary"
mv "$temporary" "$profile"
rm -f "$mapping"
trap - EXIT HUP INT TERM
