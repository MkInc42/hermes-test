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
    address=$(getent ahostsv4 "$host" | awk 'NR == 1 {print $1; exit}')
    [ -n "$address" ] || exit 1
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
